package pixelauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"image"
	"image/color"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func photo(w, h int) *image.RGBA {
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.SetRGBA(x, y, color.RGBA{R: byte(17*x + 9*y), G: byte(31*y + 7*x), B: byte(3*x + 19*y), A: 255})
		}
	}
	return im
}
func TestPixelMapReference(t *testing.T) {
	p := Policy{true, true, true}
	for turn := 0; turn < 4; turn++ {
		o := Operation{X: 1, Y: 1, Width: 5, Height: 3, ResizeWidth: 3, ResizeHeight: 2, Rotation: turn}
		// Independent reference: crop values, sample with floor, then rotate.
		input := photo(7, 5)
		base := image.NewRGBA(image.Rect(0, 0, 3, 2))
		for y := 0; y < 2; y++ {
			for x := 0; x < 3; x++ {
				base.Set(x, y, input.At(1+x*5/3, 1+y*3/2))
			}
		}
		out, err := Apply(input, o, p)
		if err != nil {
			t.Fatal(err)
		}
		ow, oh := o.Size()
		for y := 0; y < 2; y++ {
			for x := 0; x < 3; x++ {
				dx, dy := x, y
				switch turn {
				case 1:
					dx, dy = 1-y, x
				case 2:
					dx, dy = 2-x, 1-y
				case 3:
					dx, dy = y, 2-x
				}
				if out.At(dx, dy) != base.At(x, y) {
					t.Fatalf("wrong pixel for rotation %d", turn)
				}
			}
		}
		if out.Bounds().Dx() != ow || out.Bounds().Dy() != oh {
			t.Fatal("wrong size")
		}
	}
}

func TestLinkedPixelProofs(t *testing.T) {
	source := photo(7, 5)
	basis, err := GenerateBasis(35)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := basis.Encode()
	if err != nil {
		t.Fatal(err)
	}
	basisHash := Digest(cache)
	decoded, err := DecodeTrustedBasis(cache, 35, basisHash)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Points[17].Equal(&basis.Points[17]) {
		t.Fatal("cache round trip failed")
	}
	badCache := append([]byte(nil), cache...)
	badCache[len(badCache)-1] ^= 1
	if _, err := DecodeTrustedBasis(badCache, 35, basisHash); err == nil {
		t.Fatal("accepted modified generator cache")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, opening, err := Issue(basis, basisHash, source, Policy{true, true, true}, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := Trust{pub, basisHash, cert.Digest(), 35}
	chain := Chain{Version: 1, Certificate: cert, FinalOpening: opening}
	state := State{7, 5, cert.Commitment}
	if err := VerifyChain(basis, trust, chain, nil, source); err != nil {
		t.Fatal(err)
	}
	var proofs [][]byte
	var current image.Image = source
	for i, op := range []Operation{
		{X: 1, Y: 1, Width: 5, Height: 3, ResizeWidth: 3, ResizeHeight: 2, Rotation: 1},
		{X: 0, Y: 1, Width: 2, Height: 2, ResizeWidth: 1, ResizeHeight: 2, Rotation: 3},
	} {
		output, err := Apply(current, op, cert.Policy)
		if err != nil {
			t.Fatal(err)
		}
		step, encoded, nextOpening, err := ProveStep(basis, cert, chain.Steps, state, current, output, opening, op)
		if err != nil {
			t.Fatal(err)
		}
		chain.Steps = append(chain.Steps, step)
		proofs = append(proofs, encoded)
		chain.FinalOpening = nextOpening
		if err := VerifyChain(basis, trust, chain, proofs, output); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		current, opening = output, nextOpening
		state.Width, state.Height = op.Size()
		state.Commitment = step.Commitment
	}
	changed := photo(current.Bounds().Dx(), current.Bounds().Dy())
	if err := VerifyChain(basis, trust, chain, proofs, changed); err == nil {
		t.Fatal("accepted substituted pixels")
	}
	badChain := chain
	badChain.FinalOpening = append([]byte(nil), opening...)
	badChain.FinalOpening[31] ^= 1
	if err := VerifyChain(basis, trust, badChain, proofs, current); err == nil {
		t.Fatal("accepted modified final opening")
	}
	badChain = chain
	badChain.Steps = append([]Step(nil), chain.Steps...)
	badChain.Steps[0].Operation.X = 0
	if err := VerifyChain(basis, trust, badChain, proofs, current); err == nil {
		t.Fatal("accepted modified earlier operation")
	}
	badChain = chain
	badChain.Steps = append([]Step(nil), chain.Steps...)
	badChain.Steps[0].Operation.Rotation = 3
	if err := VerifyChain(basis, trust, badChain, proofs, current); err == nil {
		t.Fatal("accepted modified rotation")
	}
	badProofs := append([][]byte(nil), proofs...)
	badProofs[0] = append([]byte(nil), proofs[0]...)
	badProofs[0][len(badProofs[0])-1] ^= 1
	// Update the file digest too: the algebra, not just SHA-256, must reject it.
	badChain = chain
	badChain.Steps = append([]Step(nil), chain.Steps...)
	badChain.Steps[0].ProofDigest = Digest(badProofs[0])
	if err := VerifyChain(basis, trust, badChain, badProofs, current); err == nil {
		t.Fatal("accepted modified proof responses")
	}
	wrongTrust := trust
	wrongTrust.PublicKey = append([]byte(nil), pub...)
	wrongTrust.PublicKey[0] ^= 1
	if err := VerifyChain(basis, wrongTrust, chain, proofs, current); err == nil {
		t.Fatal("accepted wrong signer")
	}
	badChain = chain
	badChain.Certificate = cert
	badChain.Certificate.Policy.AllowResize = false
	if err := VerifyChain(basis, trust, badChain, proofs, current); err == nil {
		t.Fatal("accepted modified signed permissions")
	}
	if _, err := DecodeProof(proofs[0][:len(proofs[0])-1], 35); err == nil {
		t.Fatal("accepted truncated proof")
	}
	if _, err := DecodeProof(append(append([]byte(nil), proofs[0]...), 0), 35); err == nil {
		t.Fatal("accepted trailing proof bytes")
	}
}

func TestInvalidPixelRelationCannotBeProved(t *testing.T) {
	b, err := GenerateBasis(6)
	if err != nil {
		t.Fatal(err)
	}
	source := photo(3, 2)
	cache, _ := b.Encode()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, opening, err := Issue(b, Digest(cache), source, Policy{true, true, true}, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	op := Operation{X: 1, Width: 2, Height: 2, ResizeWidth: 2, ResizeHeight: 2}
	output, err := Apply(source, op, cert.Policy)
	if err != nil {
		t.Fatal(err)
	}
	altered := output.(*image.RGBA)
	c := altered.RGBAAt(0, 0)
	c.R ^= 1
	altered.SetRGBA(0, 0, c)
	state := State{3, 2, cert.Commitment}
	if _, _, _, err := ProveStep(b, cert, nil, state, source, altered, opening, op); err == nil {
		t.Fatal("prover accepted changed pixels")
	}
	// Construct the Schnorr responses directly, bypassing all native pixel checks.
	values, _ := Pixels(source)
	outValues, _ := Pixels(altered)
	mapping, _ := op.PixelMap(3, 2, cert.Policy)
	rs, _ := parseScalar(opening)
	ro, _ := randomScalar()
	co, _ := b.Commit(outValues, ro)
	masks := make([]fr.Element, 6)
	for i := range masks {
		masks[i], _ = randomScalar()
	}
	ks, _ := randomScalar()
	ko, _ := randomScalar()
	ts, _ := b.Commit(masks, ks)
	to, _ := b.Commit(selected(masks, mapping), ko)
	step := Step{Operation: op, Commitment: pointBytes(co)}
	p := Proof{SourceNonce: pointBytes(ts), OutputNonce: pointBytes(to), Responses: make([]fr.Element, 6)}
	challengeValue := challenge(cert, PreviousDigest(cert, nil), 0, state, step, p)
	for i := range values {
		p.Responses[i].Mul(&challengeValue, &values[i]).Add(&p.Responses[i], &masks[i])
	}
	p.SourceBlindResponse.Mul(&challengeValue, &rs).Add(&p.SourceBlindResponse, &ks)
	p.OutputBlindResponse.Mul(&challengeValue, &ro).Add(&p.OutputBlindResponse, &ko)
	encoded, _ := p.MarshalBinary()
	step.ProofDigest = Digest(encoded)
	if err := VerifyStep(b, cert, nil, state, step, encoded); err == nil {
		t.Fatal("algebra accepted an invalid pixel transformation")
	}
}

func TestPolicyAndFreshRandomness(t *testing.T) {
	base := Operation{Width: 3, Height: 2, ResizeWidth: 3, ResizeHeight: 2}
	restricted := Policy{}
	for _, mutate := range []func(*Operation){func(o *Operation) { o.X = 1; o.Width = 2; o.ResizeWidth = 2 }, func(o *Operation) { o.ResizeWidth = 1 }, func(o *Operation) { o.Rotation = 1 }, func(o *Operation) { o.X = -1 }, func(o *Operation) { o.ResizeHeight = 0 }} {
		o := base
		mutate(&o)
		if err := o.Validate(3, 2, restricted); err == nil {
			t.Fatal("accepted forbidden/invalid operation")
		}
	}
	b, _ := GenerateBasis(6)
	source := photo(3, 2)
	cache, _ := b.Encode()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cert, r, _ := Issue(b, Digest(cache), source, restricted, key)
	state := State{3, 2, cert.Commitment}
	_, p1, _, err := ProveStep(b, cert, nil, state, source, source, r, base)
	if err != nil {
		t.Fatal(err)
	}
	_, p2, _, err := ProveStep(b, cert, nil, state, source, source, r, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p1, p2) || bytes.Equal(p1[8:56], p2[8:56]) {
		t.Fatal("proof reused random masks")
	}
}
