// Package flexauth authenticates editor-selected, tile-aligned crops and quarter
// turns against one signed source. It proves the final relation to the source;
// it does not recursively attest to the history of intermediate operations.
package flexauth

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bneddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	edcurve "github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"photoproof/cropauth"
)

type Policy struct {
	Width       int  `json:"source_width"`
	Height      int  `json:"source_height"`
	Tile        int  `json:"tile_size"`
	AllowCrop   bool `json:"allow_crop"`
	AllowRotate bool `json:"allow_quarter_turns"`
}

func (p Policy) Validate() error {
	if p.Width <= 0 || p.Height <= 0 || p.Width > 16384 || p.Height > 16384 || p.Tile <= 0 || p.Tile > 16384 {
		return errors.New("invalid source dimensions or tile size")
	}
	if p.Width%p.Tile != 0 || p.Height%p.Tile != 0 {
		return errors.New("source dimensions must be tile aligned")
	}
	if (p.Width/p.Tile)*(p.Height/p.Tile) > 1024 {
		return errors.New("this prototype supports at most 1024 source tiles")
	}
	return nil
}
func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (p Policy) header() [7]int {
	return [7]int{20261013, 2, p.Width, p.Height, p.Tile, bit(p.AllowCrop), bit(p.AllowRotate)}
}

// Transform describes the final crop in ORIGINAL coordinates followed by a
// clockwise rotation in quarter turns. Coordinates are public, not secret.
type Transform struct {
	X        int `json:"x"`
	Y        int `json:"y"`
	Width    int `json:"width"`
	Height   int `json:"height"`
	Rotation int `json:"quarter_turns"`
}

func (p Policy) Identity() Transform { return Transform{Width: p.Width, Height: p.Height} }
func (t Transform) Size() (int, int) {
	if t.Rotation%2 != 0 {
		return t.Height, t.Width
	}
	return t.Width, t.Height
}
func (p Policy) ValidateTransform(t Transform) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if t.X < 0 || t.Y < 0 || t.Width <= 0 || t.Height <= 0 || t.Rotation < 0 || t.Rotation > 3 {
		return errors.New("invalid transform")
	}
	if t.X > p.Width-t.Width || t.Y > p.Height-t.Height {
		return errors.New("crop outside signed source")
	}
	for _, v := range []int{t.X, t.Y, t.Width, t.Height} {
		if v%p.Tile != 0 {
			return errors.New("crop must align to tile boundaries")
		}
	}
	if !p.AllowCrop && (t.X != 0 || t.Y != 0 || t.Width != p.Width || t.Height != p.Height) {
		return errors.New("cropping is not allowed by signer")
	}
	if !p.AllowRotate && t.Rotation != 0 {
		return errors.New("rotation is not allowed by signer")
	}
	return nil
}

// Rotate performs lossless pixel permutations; image file metadata is excluded.
func Rotate(im image.Image, turns int) *image.RGBA {
	b := im.Bounds()
	w, h := b.Dx(), b.Dy()
	turns = ((turns % 4) + 4) % 4
	ow, oh := w, h
	if turns%2 != 0 {
		ow, oh = h, w
	}
	out := image.NewRGBA(image.Rect(0, 0, ow, oh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := x, y
			switch turns {
			case 1:
				dx, dy = h-1-y, x
			case 2:
				dx, dy = w-1-x, h-1-y
			case 3:
				dx, dy = y, w-1-x
			}
			out.Set(dx, dy, im.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return out
}

// Apply crops CURRENT coordinates, then rotates. Compose maps that operation
// back to the original so later editors do not need the original pixels.
func Apply(im image.Image, edit Transform) (image.Image, error) {
	b := im.Bounds()
	if edit.X < 0 || edit.Y < 0 || edit.Width <= 0 || edit.Height <= 0 || edit.X > b.Dx()-edit.Width || edit.Y > b.Dy()-edit.Height || edit.Rotation < 0 || edit.Rotation > 3 {
		return nil, errors.New("invalid edit for current image")
	}
	crop := image.NewRGBA(image.Rect(0, 0, edit.Width, edit.Height))
	draw.Draw(crop, crop.Bounds(), im, b.Min.Add(image.Pt(edit.X, edit.Y)), draw.Src)
	return Rotate(crop, edit.Rotation), nil
}
func Compose(p Policy, previous, edit Transform) (Transform, error) {
	if err := p.ValidateTransform(previous); err != nil {
		return Transform{}, err
	}
	w, h := previous.Size()
	if edit.X < 0 || edit.Y < 0 || edit.Width <= 0 || edit.Height <= 0 || edit.X > w-edit.Width || edit.Y > h-edit.Height || edit.Rotation < 0 || edit.Rotation > 3 {
		return Transform{}, errors.New("edit outside current image")
	}
	if !p.AllowRotate && edit.Rotation != 0 {
		return Transform{}, errors.New("rotation is not allowed by signer")
	}
	u, v, cw, ch := edit.X, edit.Y, edit.Width, edit.Height
	switch previous.Rotation {
	case 1:
		u, v, cw, ch = edit.Y, previous.Height-edit.X-edit.Width, edit.Height, edit.Width
	case 2:
		u, v = previous.Width-edit.X-edit.Width, previous.Height-edit.Y-edit.Height
	case 3:
		u, v, cw, ch = previous.Width-edit.Y-edit.Height, edit.X, edit.Height, edit.Width
	}
	result := Transform{previous.X + u, previous.Y + v, cw, ch, (previous.Rotation + edit.Rotation) % 4}
	return result, p.ValidateTransform(result)
}

type Circuit struct {
	Policy     Policy               `gnark:"-"`
	Header     [7]frontend.Variable `gnark:",public"`
	X          frontend.Variable    `gnark:",public"`
	Y          frontend.Variable    `gnark:",public"`
	Width      frontend.Variable    `gnark:",public"`
	Height     frontend.Variable    `gnark:",public"`
	Rotation   frontend.Variable    `gnark:",public"`
	Output     []frontend.Variable  `gnark:",public"`
	Commitment frontend.Variable    `gnark:",public"`
	PublicKey  eddsa.PublicKey      `gnark:",public"`
	Signature  eddsa.Signature      `gnark:",public"`
	Source     []frontend.Variable  `gnark:",secret"`
}

func newCircuit(p Policy) *Circuit {
	n := 2 * (p.Width / p.Tile) * (p.Height / p.Tile)
	return &Circuit{Policy: p, Source: make([]frontend.Variable, n), Output: make([]frontend.Variable, n)}
}

// oneHot restricts v to a small integer interval even for adversarial witnesses.
func oneHot(api frontend.API, v frontend.Variable, start, count int) []frontend.Variable {
	s := make([]frontend.Variable, count)
	var sum frontend.Variable = 0
	for i := range s {
		s[i] = api.IsZero(api.Sub(v, start+i))
		sum = api.Add(sum, s[i])
	}
	api.AssertIsEqual(sum, 1)
	return s
}
func (c *Circuit) Define(api frontend.API) error {
	p := c.Policy
	cols, rows := p.Width/p.Tile, p.Height/p.Tile
	xs, ys := oneHot(api, c.X, 0, cols), oneHot(api, c.Y, 0, rows)
	ws, hs := oneHot(api, c.Width, 1, cols), oneHot(api, c.Height, 1, rows)
	api.AssertIsLessOrEqual(api.Add(c.X, c.Width), cols)
	api.AssertIsLessOrEqual(api.Add(c.Y, c.Height), rows)
	api.ToBinary(c.Rotation, 2)
	if !p.AllowRotate {
		api.AssertIsEqual(c.Rotation, 0)
	}
	if !p.AllowCrop {
		api.AssertIsEqual(c.X, 0)
		api.AssertIsEqual(c.Y, 0)
		api.AssertIsEqual(c.Width, cols)
		api.AssertIsEqual(c.Height, rows)
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i, v := range p.header() {
		api.AssertIsEqual(c.Header[i], v)
		h.Write(c.Header[i])
	}
	for _, v := range c.Source {
		api.ToBinary(v, 128)
		h.Write(v)
	}
	api.AssertIsEqual(h.Sum(), c.Commitment)
	// Shift rows, then columns, using constrained selectors. This avoids quadratic
	// scanning of all source tiles separately for every output tile.
	shifted := make([]frontend.Variable, len(c.Source))
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			for limb := 0; limb < 2; limb++ {
				var sum frontend.Variable = 0
				for sy := y; sy < rows; sy++ {
					sum = api.Add(sum, api.Mul(ys[sy-y], c.Source[2*(sy*cols+x)+limb]))
				}
				shifted[2*(y*cols+x)+limb] = sum
			}
		}
	}
	for y := 0; y < rows; y++ {
		var rowActive frontend.Variable = 0
		for i := y; i < rows; i++ {
			rowActive = api.Add(rowActive, hs[i])
		}
		for x := 0; x < cols; x++ {
			var colActive frontend.Variable = 0
			for i := x; i < cols; i++ {
				colActive = api.Add(colActive, ws[i])
			}
			active := api.Mul(rowActive, colActive)
			for limb := 0; limb < 2; limb++ {
				var sum frontend.Variable = 0
				for sx := x; sx < cols; sx++ {
					sum = api.Add(sum, api.Mul(xs[sx-x], shifted[2*(y*cols+sx)+limb]))
				}
				api.AssertIsEqual(c.Output[2*(y*cols+x)+limb], api.Mul(active, sum))
			}
		}
	}
	curve, err := edcurve.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	h.Reset()
	return eddsa.Verify(curve, c.Signature, c.Commitment, c.PublicKey, &h)
}

func Compile(p Policy) (constraint.ConstraintSystem, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newCircuit(p))
}

type Parameters struct {
	Policy Policy
	CS     constraint.ConstraintSystem
	PK     groth16.ProvingKey
	VK     groth16.VerifyingKey
}

func Setup(p Policy) (*Parameters, error) {
	cs, err := Compile(p)
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}
	return &Parameters{p, cs, pk, vk}, nil
}

// EditorData is PRIVATE auxiliary data, never required by the verifier.
// It contains source tile digests, not original pixels or a signing secret.
type EditorData struct {
	Certificate cropauth.Certificate `json:"certificate"`
	Hashes      []string             `json:"source_tile_limbs"`
}

func commitment(p Policy, values []*big.Int) []byte {
	h := hash.MIMC_BN254.New()
	write := func(v *big.Int) { var f fr.Element; f.SetBigInt(v); h.Write(f.Marshal()) }
	for _, v := range p.header() {
		write(big.NewInt(int64(v)))
	}
	for _, v := range values {
		write(v)
	}
	return h.Sum(nil)
}
func Issue(p Policy, source image.Image, signer signature.Signer) (EditorData, error) {
	if err := p.Validate(); err != nil {
		return EditorData{}, err
	}
	if source.Bounds().Dx() != p.Width || source.Bounds().Dy() != p.Height {
		return EditorData{}, errors.New("source dimensions mismatch")
	}
	values, err := cropauth.TileHashes(source, p.Tile)
	if err != nil {
		return EditorData{}, err
	}
	m := commitment(p, values)
	sig, err := signer.Sign(m, hash.MIMC_BN254.New())
	if err != nil {
		return EditorData{}, err
	}
	data := EditorData{Certificate: cropauth.Certificate{Commitment: m, Signature: sig}}
	for _, v := range values {
		data.Hashes = append(data.Hashes, v.Text(16))
	}
	return data, nil
}
func validateCertificate(pub []byte, cert cropauth.Certificate) error {
	if len(pub) != 32 || len(cert.Signature) != 64 || len(cert.Commitment) != 32 {
		return errors.New("invalid certificate encoding")
	}
	var f fr.Element
	if err := f.SetBytesCanonical(cert.Commitment); err != nil {
		return err
	}
	var key bneddsa.PublicKey
	if _, err := key.SetBytes(pub); err != nil {
		return err
	}
	ok, err := key.Verify(cert.Signature, cert.Commitment, hash.MIMC_BN254.New())
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid source signature")
	}
	return nil
}
func assignment(p Policy, t Transform, pub []byte, cert cropauth.Certificate, output image.Image) (*Circuit, error) {
	if err := p.ValidateTransform(t); err != nil {
		return nil, err
	}
	if err := validateCertificate(pub, cert); err != nil {
		return nil, err
	}
	w, h := t.Size()
	if output.Bounds().Dx() != w || output.Bounds().Dy() != h {
		return nil, errors.New("received image dimensions do not match transform")
	}
	// Inverse rotation is deterministic and only reorders pixels. Actual received
	// pixels, not an editor-supplied hash list, always form the public witness.
	canonical := Rotate(output, (4-t.Rotation)%4)
	values, err := cropauth.TileHashes(canonical, p.Tile)
	if err != nil {
		return nil, err
	}
	a := newCircuit(p)
	for i, v := range p.header() {
		a.Header[i] = v
	}
	a.X, a.Y, a.Width, a.Height, a.Rotation = t.X/p.Tile, t.Y/p.Tile, t.Width/p.Tile, t.Height/p.Tile, t.Rotation
	a.Commitment = cert.Commitment
	a.PublicKey.Assign(twistededwards.BN254, pub)
	a.Signature.Assign(twistededwards.BN254, cert.Signature)
	for i := range a.Output {
		a.Output[i] = 0
	}
	cols, cropCols := p.Width/p.Tile, t.Width/p.Tile
	for y := 0; y < t.Height/p.Tile; y++ {
		for x := 0; x < cropCols; x++ {
			for limb := 0; limb < 2; limb++ {
				a.Output[2*(y*cols+x)+limb] = values[2*(y*cropCols+x)+limb]
			}
		}
	}
	return a, nil
}
func Prove(params *Parameters, t Transform, pub []byte, data EditorData, output image.Image) (groth16.Proof, error) {
	a, err := assignment(params.Policy, t, pub, data.Certificate, output)
	if err != nil {
		return nil, err
	}
	if len(data.Hashes) != len(a.Source) {
		return nil, errors.New("invalid editor hash count")
	}
	values := make([]*big.Int, len(data.Hashes))
	for i, s := range data.Hashes {
		v, ok := new(big.Int).SetString(s, 16)
		if !ok || v.Sign() < 0 || v.BitLen() > 128 {
			return nil, errors.New("invalid editor hash limb")
		}
		values[i] = v
		a.Source[i] = v
	}
	if !bytes.Equal(commitment(params.Policy, values), data.Certificate.Commitment) {
		return nil, errors.New("editor data does not match signed source")
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return groth16.Prove(params.CS, params.PK, w)
}
func Verify(p Policy, t Transform, pub []byte, vk groth16.VerifyingKey, cert cropauth.Certificate, proof groth16.Proof, output image.Image) error {
	if vk == nil || proof == nil {
		return errors.New("missing verifying key or proof")
	}
	a, err := assignment(p, t, pub, cert, output)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("received image/proof mismatch: %w", err)
	}
	return nil
}
