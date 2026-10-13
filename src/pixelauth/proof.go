// This is an experimental generalized Schnorr proof of two linked openings,
// Fiat-Shamir transformed with SHA-512. It is not a succinct SNARK.
package pixelauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Certificate struct {
	Version         int    `json:"version"`
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	Policy          Policy `json:"policy"`
	GeneratorDigest string `json:"generator_sha256"`
	Commitment      []byte `json:"source_commitment"`
	Signature       []byte `json:"signature"`
}

func (c Certificate) payload() []byte {
	c.Signature = nil
	b, _ := json.Marshal(c)
	return append([]byte("PhotoProof/pixel-certificate/v1\x00"), b...)
}
func (c Certificate) Digest() string { b, _ := json.Marshal(c); return Digest(b) }

type Trust struct {
	PublicKey         []byte `json:"signer_public_key"`
	GeneratorDigest   string `json:"generator_sha256"`
	CertificateDigest string `json:"source_certificate_sha256"`
	Pixels            int    `json:"generators"`
}

func Issue(b *Basis, generatorDigest string, im image.Image, p Policy, key ed25519.PrivateKey) (Certificate, []byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Certificate{}, nil, errors.New("invalid signing key")
	}
	values, err := Pixels(im)
	if err != nil {
		return Certificate{}, nil, err
	}
	if err := validateBasis(b, len(values)); err != nil {
		return Certificate{}, nil, err
	}
	r, err := randomScalar()
	if err != nil {
		return Certificate{}, nil, err
	}
	c, err := b.Commit(values, r)
	if err != nil {
		return Certificate{}, nil, err
	}
	cert := Certificate{Version: 1, Width: im.Bounds().Dx(), Height: im.Bounds().Dy(), Policy: p, GeneratorDigest: generatorDigest, Commitment: pointBytes(c)}
	cert.Signature = ed25519.Sign(key, cert.payload())
	return cert, scalarBytes(r), nil
}
func (c Certificate) Validate(t Trust) error {
	if c.Version != 1 || len(t.PublicKey) != ed25519.PublicKeySize || len(c.Signature) != ed25519.SignatureSize {
		return errors.New("invalid certificate")
	}
	if err := dimensions(c.Width, c.Height); err != nil {
		return err
	}
	if c.Width*c.Height != t.Pixels || c.GeneratorDigest != t.GeneratorDigest || c.Digest() != t.CertificateDigest {
		return errors.New("certificate does not match trusted source")
	}
	if !ed25519.Verify(ed25519.PublicKey(t.PublicKey), c.payload(), c.Signature) {
		return errors.New("invalid source signature")
	}
	_, err := parsePoint(c.Commitment)
	return err
}

type Step struct {
	Operation   Operation `json:"operation"`
	Commitment  []byte    `json:"output_commitment"`
	ProofDigest string    `json:"proof_sha256"`
}
type Chain struct {
	Version     int         `json:"version"`
	Certificate Certificate `json:"certificate"`
	Steps       []Step      `json:"steps"`
	// Only the CURRENT image opening is public. Prior openings and prior pixels
	// are not copied into the next bundle.
	FinalOpening []byte `json:"final_image_opening"`
}
type State struct {
	Width      int
	Height     int
	Commitment []byte
}

type Proof struct {
	SourceNonce         []byte
	OutputNonce         []byte
	Responses           []fr.Element
	SourceBlindResponse fr.Element
	OutputBlindResponse fr.Element
}

func (p Proof) MarshalBinary() ([]byte, error) {
	if len(p.Responses) == 0 || len(p.Responses) > MaxPixels || len(p.SourceNonce) != 48 || len(p.OutputNonce) != 48 {
		return nil, errors.New("invalid proof encoding")
	}
	buf := make([]byte, 168+32*len(p.Responses))
	copy(buf[:4], "PXL1")
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(p.Responses)))
	copy(buf[8:56], p.SourceNonce)
	copy(buf[56:104], p.OutputNonce)
	copy(buf[104:136], scalarBytes(p.SourceBlindResponse))
	copy(buf[136:168], scalarBytes(p.OutputBlindResponse))
	for i, v := range p.Responses {
		copy(buf[168+32*i:200+32*i], scalarBytes(v))
	}
	return buf, nil
}
func DecodeProof(data []byte, n int) (Proof, error) {
	var p Proof
	if n <= 0 || n > MaxPixels || len(data) != 168+32*n || !bytes.Equal(data[:4], []byte("PXL1")) || int(binary.BigEndian.Uint32(data[4:8])) != n {
		return p, errors.New("invalid proof length/header")
	}
	p.SourceNonce = append([]byte(nil), data[8:56]...)
	p.OutputNonce = append([]byte(nil), data[56:104]...)
	if _, err := parsePoint(p.SourceNonce); err != nil {
		return p, err
	}
	if _, err := parsePoint(p.OutputNonce); err != nil {
		return p, err
	}
	var err error
	p.SourceBlindResponse, err = parseScalar(data[104:136])
	if err != nil {
		return p, err
	}
	p.OutputBlindResponse, err = parseScalar(data[136:168])
	if err != nil {
		return p, err
	}
	p.Responses = make([]fr.Element, n)
	for i := range p.Responses {
		if err := p.Responses[i].SetBytesCanonical(data[168+32*i : 200+32*i]); err != nil {
			return p, err
		}
	}
	return p, nil
}

func challenge(cert Certificate, previousDigest string, index int, state State, step Step, p Proof) fr.Element {
	h := sha512.New()
	write := func(data []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(data)))
		h.Write(n[:])
		h.Write(data)
	}
	write([]byte("PhotoProof/linked-pixel-openings/FS/v1"))
	write([]byte(cert.Digest()))
	write([]byte(previousDigest))
	metadata, _ := json.Marshal(struct {
		Index     int
		Width     int
		Height    int
		Operation Operation
	}{index, state.Width, state.Height, step.Operation})
	write(metadata)
	write(state.Commitment)
	write(step.Commitment)
	write(p.SourceNonce)
	write(p.OutputNonce)
	var c fr.Element
	c.SetBytes(h.Sum(nil))
	return c
}
func selected(values []fr.Element, mapping []int) []fr.Element {
	out := make([]fr.Element, len(mapping))
	for i, j := range mapping {
		out[i] = values[j]
	}
	return out
}
func PreviousDigest(cert Certificate, steps []Step) string {
	// Step metadata binds each previous proof digest, giving an ordered chain.
	if len(steps) == 0 {
		steps = []Step{}
	}
	b, _ := json.Marshal(struct {
		Root  string
		Steps []Step
	}{cert.Digest(), steps})
	return Digest(b)
}

func ProveStep(b *Basis, cert Certificate, prior []Step, state State, source, output image.Image, sourceOpening []byte, operation Operation) (Step, []byte, []byte, error) {
	var step Step
	if len(prior) >= 64 {
		return step, nil, nil, errors.New("at most 64 editing steps are supported")
	}
	if source.Bounds().Dx() != state.Width || source.Bounds().Dy() != state.Height {
		return step, nil, nil, errors.New("input dimensions differ from previous image")
	}
	mapping, err := operation.PixelMap(state.Width, state.Height, cert.Policy)
	if err != nil {
		return step, nil, nil, err
	}
	w, h := operation.Size()
	if output.Bounds().Dx() != w || output.Bounds().Dy() != h {
		return step, nil, nil, errors.New("incorrect output dimensions")
	}
	values, err := Pixels(source)
	if err != nil {
		return step, nil, nil, err
	}
	outValues, err := Pixels(output)
	if err != nil {
		return step, nil, nil, err
	}
	for i, j := range mapping {
		if !outValues[i].Equal(&values[j]) {
			return step, nil, nil, errors.New("output pixels do not match permitted operation")
		}
	}
	rs, err := parseScalar(sourceOpening)
	if err != nil {
		return step, nil, nil, err
	}
	cs, err := parsePoint(state.Commitment)
	if err != nil {
		return step, nil, nil, err
	}
	actual, err := b.Commit(values, rs)
	if err != nil {
		return step, nil, nil, err
	}
	if !actual.Equal(&cs) {
		return step, nil, nil, errors.New("input pixels/opening do not match previous commitment")
	}
	ro, err := randomScalar()
	if err != nil {
		return step, nil, nil, err
	}
	co, err := b.Commit(outValues, ro)
	if err != nil {
		return step, nil, nil, err
	}
	step = Step{Operation: operation, Commitment: pointBytes(co)}
	masks := make([]fr.Element, len(values))
	for i := range masks {
		masks[i], err = randomScalar()
		if err != nil {
			return step, nil, nil, err
		}
	}
	ks, err := randomScalar()
	if err != nil {
		return step, nil, nil, err
	}
	ko, err := randomScalar()
	if err != nil {
		return step, nil, nil, err
	}
	ts, err := b.Commit(masks, ks)
	if err != nil {
		return step, nil, nil, err
	}
	to, err := b.Commit(selected(masks, mapping), ko)
	if err != nil {
		return step, nil, nil, err
	}
	p := Proof{SourceNonce: pointBytes(ts), OutputNonce: pointBytes(to), Responses: make([]fr.Element, len(values))}
	c := challenge(cert, PreviousDigest(cert, prior), len(prior), state, step, p)
	for i := range values {
		p.Responses[i].Mul(&c, &values[i]).Add(&p.Responses[i], &masks[i])
	}
	p.SourceBlindResponse.Mul(&c, &rs).Add(&p.SourceBlindResponse, &ks)
	p.OutputBlindResponse.Mul(&c, &ro).Add(&p.OutputBlindResponse, &ko)
	encoded, err := p.MarshalBinary()
	if err != nil {
		return step, nil, nil, err
	}
	step.ProofDigest = Digest(encoded)
	return step, encoded, scalarBytes(ro), nil
}

func VerifyStep(b *Basis, cert Certificate, prior []Step, state State, step Step, encoded []byte) error {
	mapping, err := step.Operation.PixelMap(state.Width, state.Height, cert.Policy)
	if err != nil {
		return err
	}
	if step.ProofDigest != Digest(encoded) {
		return errors.New("proof digest mismatch")
	}
	if err := validateBasis(b, state.Width*state.Height); err != nil {
		return err
	}
	cs, err := parsePoint(state.Commitment)
	if err != nil {
		return err
	}
	co, err := parsePoint(step.Commitment)
	if err != nil {
		return err
	}
	p, err := DecodeProof(encoded, state.Width*state.Height)
	if err != nil {
		return err
	}
	ts, err := parsePoint(p.SourceNonce)
	if err != nil {
		return err
	}
	to, err := parsePoint(p.OutputNonce)
	if err != nil {
		return err
	}
	c := challenge(cert, PreviousDigest(cert, prior), len(prior), state, step, p)
	left, err := b.Commit(p.Responses, p.SourceBlindResponse)
	if err != nil {
		return err
	}
	right := scalarPoint(&cs, &c)
	right.Add(&right, &ts)
	if !left.Equal(&right) {
		return errors.New("source opening relation failed")
	}
	left, err = b.Commit(selected(p.Responses, mapping), p.OutputBlindResponse)
	if err != nil {
		return err
	}
	right = scalarPoint(&co, &c)
	right.Add(&right, &to)
	if !left.Equal(&right) {
		return errors.New("edited pixel relation failed")
	}
	return nil
}

func ChainState(chain Chain) (State, error) {
	state := State{chain.Certificate.Width, chain.Certificate.Height, chain.Certificate.Commitment}
	for _, step := range chain.Steps {
		if err := step.Operation.Validate(state.Width, state.Height, chain.Certificate.Policy); err != nil {
			return state, err
		}
		state.Width, state.Height = step.Operation.Size()
		if _, err := parsePoint(step.Commitment); err != nil {
			return state, err
		}
		state.Commitment = step.Commitment
	}
	return state, nil
}
func VerifyChain(b *Basis, trust Trust, chain Chain, proofs [][]byte, output image.Image) error {
	if chain.Version != 1 || len(chain.Steps) > 64 || len(proofs) != len(chain.Steps) {
		return errors.New("invalid chain version or proof count")
	}
	if err := chain.Certificate.Validate(trust); err != nil {
		return err
	}
	if err := validateBasis(b, trust.Pixels); err != nil {
		return err
	}
	final, err := ChainState(chain)
	if err != nil {
		return err
	}
	if output.Bounds().Dx() != final.Width || output.Bounds().Dy() != final.Height {
		return errors.New("received image has incorrect dimensions")
	}
	values, err := Pixels(output)
	if err != nil {
		return err
	}
	r, err := parseScalar(chain.FinalOpening)
	if err != nil {
		return err
	}
	actual, err := b.Commit(values, r)
	if err != nil {
		return err
	}
	expected, err := parsePoint(final.Commitment)
	if err != nil {
		return err
	}
	if !actual.Equal(&expected) {
		return errors.New("received image pixels do not match proof chain")
	}
	state := State{chain.Certificate.Width, chain.Certificate.Height, chain.Certificate.Commitment}
	for i, step := range chain.Steps {
		if err := VerifyStep(b, chain.Certificate, chain.Steps[:i], state, step, proofs[i]); err != nil {
			return fmt.Errorf("step %d: %w", i+1, err)
		}
		state.Width, state.Height = step.Operation.Size()
		state.Commitment = step.Commitment
	}
	return nil
}
