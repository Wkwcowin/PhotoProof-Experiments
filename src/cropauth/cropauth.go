// Package cropauth implements a restricted, signed, tile-aligned crop experiment.
// SHA-256 tile hashes are computed by the signer and verifier outside the SNARK.
// The circuit authenticates their ordered commitment and enforces crop selection.
package cropauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bneddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	ceddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	edcurve "github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// Policy is fixed in the circuit and signed with the source commitment.
// X,Y,Width,Height specify ONE exact permitted crop, in pixels.
type Policy struct {
	SourceWidth  int `json:"source_width"`
	SourceHeight int `json:"source_height"`
	Tile         int `json:"tile_size"`
	X            int `json:"crop_x"`
	Y            int `json:"crop_y"`
	Width        int `json:"crop_width"`
	Height       int `json:"crop_height"`
}

func (p Policy) Validate() error {
	if p.Tile <= 0 || p.SourceWidth <= 0 || p.SourceHeight <= 0 || p.Width <= 0 || p.Height <= 0 || p.X < 0 || p.Y < 0 {
		return errors.New("invalid crop dimensions")
	}
	if p.SourceWidth > 16384 || p.SourceHeight > 16384 || p.Tile > 16384 {
		return errors.New("dimensions exceed experiment limits")
	}
	if p.X > p.SourceWidth-p.Width || p.Y > p.SourceHeight-p.Height {
		return errors.New("crop outside source image")
	}
	for _, n := range []int{p.SourceWidth, p.SourceHeight, p.X, p.Y, p.Width, p.Height} {
		if n%p.Tile != 0 {
			return errors.New("dimensions and crop must align to tile boundaries")
		}
	}
	if p.SourceWidth/p.Tile*(p.SourceHeight/p.Tile) > 4096 {
		return errors.New("too many tiles")
	}
	return nil
}

func (p Policy) header() []int {
	// Version/domain tag prevents cross-protocol reuse of this commitment.
	return []int{20261013, 1, p.SourceWidth, p.SourceHeight, p.Tile, p.X, p.Y, p.Width, p.Height}
}

type Circuit struct {
	Policy     Policy               `gnark:"-"`
	Header     [9]frontend.Variable `gnark:",public"`
	Source     []frontend.Variable  `gnark:",secret"`
	Output     []frontend.Variable  `gnark:",public"`
	Commitment frontend.Variable    `gnark:",public"`
	PublicKey  eddsa.PublicKey      `gnark:",public"`
	Signature  eddsa.Signature      `gnark:",public"`
}

func circuit(p Policy) *Circuit {
	return &Circuit{Policy: p, Source: make([]frontend.Variable, 2*(p.SourceWidth/p.Tile)*(p.SourceHeight/p.Tile)),
		Output: make([]frontend.Variable, 2*(p.Width/p.Tile)*(p.Height/p.Tile))}
}

func (c *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	for i, v := range c.Policy.header() {
		api.AssertIsEqual(c.Header[i], v)
		h.Write(c.Header[i])
	}
	for _, v := range c.Source {
		// Each SHA-256 digest is represented losslessly by two 128-bit limbs.
		api.ToBinary(v, 128)
		h.Write(v)
	}
	api.AssertIsEqual(h.Sum(), c.Commitment)
	p := c.Policy
	srcCols, outCols := p.SourceWidth/p.Tile, p.Width/p.Tile
	for y := 0; y < p.Height/p.Tile; y++ {
		for x := 0; x < outCols; x++ {
			src := 2 * ((y+p.Y/p.Tile)*srcCols + x + p.X/p.Tile)
			dst := 2 * (y*outCols + x)
			api.AssertIsEqual(c.Output[dst], c.Source[src])
			api.AssertIsEqual(c.Output[dst+1], c.Source[src+1])
		}
	}
	curve, err := edcurve.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	h.Reset()
	return eddsa.Verify(curve, c.Signature, c.Commitment, c.PublicKey, &h)
}

type Parameters struct {
	Policy Policy
	CS     constraint.ConstraintSystem
	PK     groth16.ProvingKey
	VK     groth16.VerifyingKey
}

func Setup(p Policy) (*Parameters, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit(p))
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}
	return &Parameters{p, cs, pk, vk}, nil
}

func NewSigner() (signature.Signer, error) { return ceddsa.New(twistededwards.BN254, rand.Reader) }

// Certificate contains a signed source commitment, not a replacement trust root.
type Certificate struct {
	Commitment []byte `json:"source_commitment"`
	Signature  []byte `json:"signature"`
}

func ReadImage(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	im, _, err := image.Decode(f)
	return im, err
}

func SavePNG(path string, im image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, im); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Pixel hashes ignore file encoding and metadata, but preserve all RGB pixels.
// Transparent images are rejected to avoid different interpretations of RGB.
func tileHashes(im image.Image, tile int) ([]*big.Int, error) {
	b := im.Bounds()
	if tile <= 0 || b.Dx()%tile != 0 || b.Dy()%tile != 0 {
		return nil, errors.New("image does not align with tiles")
	}
	var result []*big.Int
	for ty := 0; ty < b.Dy(); ty += tile {
		for tx := 0; tx < b.Dx(); tx += tile {
			h := sha256.New()
			h.Write([]byte("PhotoProof/RGB8/tile/v1"))
			var size [4]byte
			binary.BigEndian.PutUint32(size[:], uint32(tile))
			h.Write(size[:])
			for y := 0; y < tile; y++ {
				for x := 0; x < tile; x++ {
					r, g, bl, a := im.At(b.Min.X+tx+x, b.Min.Y+ty+y).RGBA()
					if a != 65535 {
						return nil, errors.New("only opaque RGB images are supported")
					}
					h.Write([]byte{byte(r >> 8), byte(g >> 8), byte(bl >> 8)})
				}
			}
			digest := h.Sum(nil)
			result = append(result, new(big.Int).SetBytes(digest[:16]), new(big.Int).SetBytes(digest[16:]))
		}
	}
	return result, nil
}

// TileHashes exposes the canonical RGB8 tile encoding to later experiments.
func TileHashes(im image.Image, tile int) ([]*big.Int, error) {
	return tileHashes(im, tile)
}

func sourceHashes(p Policy, im image.Image) ([]*big.Int, error) {
	if im.Bounds().Dx() != p.SourceWidth || im.Bounds().Dy() != p.SourceHeight {
		return nil, errors.New("source dimensions do not match policy")
	}
	return tileHashes(im, p.Tile)
}

func commitment(p Policy, limbs []*big.Int) []byte {
	h := hash.MIMC_BN254.New()
	write := func(v *big.Int) { var f fr.Element; f.SetBigInt(v); h.Write(f.Marshal()) }
	for _, v := range p.header() {
		write(big.NewInt(int64(v)))
	}
	for _, v := range limbs {
		write(v)
	}
	return h.Sum(nil)
}

func SignOriginal(p Policy, im image.Image, signer signature.Signer) (Certificate, error) {
	if err := p.Validate(); err != nil {
		return Certificate{}, err
	}
	limbs, err := sourceHashes(p, im)
	if err != nil {
		return Certificate{}, err
	}
	m := commitment(p, limbs)
	sig, err := signer.Sign(m, hash.MIMC_BN254.New())
	return Certificate{m, sig}, err
}

func publicAssignment(p Policy, publicKey []byte, cert Certificate, output image.Image) (*Circuit, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(publicKey) != 32 || len(cert.Signature) != 64 || len(cert.Commitment) != 32 {
		return nil, errors.New("invalid certificate encoding")
	}
	var f fr.Element
	if err := f.SetBytesCanonical(cert.Commitment); err != nil {
		return nil, err
	}
	// Native validation rejects malformed points before gnark Assign (which panics).
	var pub bneddsa.PublicKey
	if _, err := pub.SetBytes(publicKey); err != nil {
		return nil, errors.New("invalid signer public key")
	}
	ok, err := pub.Verify(cert.Signature, cert.Commitment, hash.MIMC_BN254.New())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid source signature")
	}
	if output.Bounds().Dx() != p.Width || output.Bounds().Dy() != p.Height {
		return nil, errors.New("output dimensions do not match signed crop")
	}
	limbs, err := tileHashes(output, p.Tile)
	if err != nil {
		return nil, err
	}
	a := circuit(p)
	for i, v := range p.header() {
		a.Header[i] = v
	}
	a.Commitment = cert.Commitment
	a.PublicKey.Assign(twistededwards.BN254, publicKey)
	a.Signature.Assign(twistededwards.BN254, cert.Signature)
	for i, v := range limbs {
		a.Output[i] = v
	}
	return a, nil
}

func Prove(params *Parameters, publicKey []byte, cert Certificate, source, output image.Image) (groth16.Proof, error) {
	a, err := publicAssignment(params.Policy, publicKey, cert, output)
	if err != nil {
		return nil, err
	}
	limbs, err := sourceHashes(params.Policy, source)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(commitment(params.Policy, limbs), cert.Commitment) {
		return nil, errors.New("source differs from signed image")
	}
	for i, v := range limbs {
		a.Source[i] = v
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return groth16.Prove(params.CS, params.PK, w)
}

// Verify reconstructs public inputs from the ACTUAL received image.
// p, publicKey and vk must be supplied by a trusted source, not the editor.
func Verify(p Policy, publicKey []byte, vk groth16.VerifyingKey, cert Certificate, proof groth16.Proof, output image.Image) error {
	if proof == nil || vk == nil {
		return errors.New("missing proof or verifying key")
	}
	a, err := publicAssignment(p, publicKey, cert, output)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("image/proof verification failed: %w", err)
	}
	return nil
}
