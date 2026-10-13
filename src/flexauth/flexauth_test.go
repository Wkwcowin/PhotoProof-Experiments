package flexauth

import (
	"bytes"
	"image"
	"image/color"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"photoproof/cropauth"
)

func sample(w, h int) *image.RGBA {
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			im.SetRGBA(x, y, color.RGBA{R: byte(17*x + 7*y), G: byte(31*y + 3*x), B: byte(5*x + 19*y), A: 255})
		}
	}
	return im
}

func TestEditorSelectedTransforms(t *testing.T) {
	p := Policy{Width: 6, Height: 4, Tile: 2, AllowCrop: true, AllowRotate: true}
	source := sample(6, 4)
	params, err := Setup(p)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cropauth.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().Bytes()
	data, err := Issue(p, source, signer)
	if err != nil {
		t.Fatal(err)
	}
	// The SAME certificate and setup verify different positions, sizes and turns.
	for i, tr := range []Transform{
		p.Identity(), {X: 2, Width: 4, Height: 4}, {X: 4, Y: 2, Width: 2, Height: 2},
		{X: 2, Width: 4, Height: 2, Rotation: 1}, {Width: 2, Height: 4, Rotation: 2}, {X: 2, Y: 2, Width: 4, Height: 2, Rotation: 3},
	} {
		output, err := Apply(source, tr)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := Prove(params, tr, pub, data, output)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if err := Verify(p, tr, pub, params.VK, data.Certificate, proof, output); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	tr := Transform{X: 2, Width: 2, Height: 2, Rotation: 1}
	output, _ := Apply(source, tr)
	proof, err := Prove(params, tr, pub, data, output)
	if err != nil {
		t.Fatal(err)
	}
	changed := Rotate(output, 0)
	c := changed.RGBAAt(0, 0)
	c.R ^= 1
	changed.SetRGBA(0, 0, c)
	if err := Verify(p, tr, pub, params.VK, data.Certificate, proof, changed); err == nil {
		t.Fatal("accepted changed pixel")
	}
	if _, err := Prove(params, tr, pub, data, changed); err == nil {
		t.Fatal("generated proof for changed pixel")
	}
	wrong := tr
	wrong.X = 0
	if err := Verify(p, wrong, pub, params.VK, data.Certificate, proof, output); err == nil {
		t.Fatal("accepted substituted crop coordinates")
	}
	wrong = tr
	wrong.Rotation = 2
	if err := Verify(p, wrong, pub, params.VK, data.Certificate, proof, output); err == nil {
		t.Fatal("accepted substituted rotation")
	}
	other, err := cropauth.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(p, tr, other.Public().Bytes(), params.VK, data.Certificate, proof, output); err == nil {
		t.Fatal("accepted untrusted signer")
	}
	t.Run("circuit rejects adversarial witnesses", func(t *testing.T) {
		for name, mutate := range map[string]func(*Circuit){
			"negative x": func(a *Circuit) { a.X = -1 }, "outside x": func(a *Circuit) { a.X = 3 },
			"zero width": func(a *Circuit) { a.Width = 0 }, "oversized crop": func(a *Circuit) { a.Width = 3 },
			"invalid rotation":      func(a *Circuit) { a.Rotation = 4 },
			"nonzero padding":       func(a *Circuit) { a.Output[len(a.Output)-1] = 1 },
			"unsigned source":       func(a *Circuit) { a.Source[0] = 1 },
			"changed signed policy": func(a *Circuit) { a.Header[6] = 0 },
		} {
			t.Run(name, func(t *testing.T) {
				a, err := assignment(p, tr, pub, data.Certificate, output)
				if err != nil {
					t.Fatal(err)
				}
				for i, v := range data.Hashes {
					a.Source[i] = "0x" + v
				}
				mutate(a)
				w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := groth16.Prove(params.CS, params.PK, w); err == nil {
					t.Fatal("circuit accepted invalid witness")
				}
			})
		}
	})
}

func TestComposeAllQuarterTurns(t *testing.T) {
	p := Policy{Width: 8, Height: 6, Tile: 1, AllowCrop: true, AllowRotate: true}
	source := sample(8, 6)
	for before := 0; before < 4; before++ {
		for after := 0; after < 4; after++ {
			previous := Transform{X: 1, Y: 1, Width: 6, Height: 4, Rotation: before}
			current, err := Apply(source, previous)
			if err != nil {
				t.Fatal(err)
			}
			w, h := previous.Size()
			edit := Transform{X: 1, Y: 1, Width: w - 2, Height: h - 2, Rotation: after}
			sequential, err := Apply(current, edit)
			if err != nil {
				t.Fatal(err)
			}
			combined, err := Compose(p, previous, edit)
			if err != nil {
				t.Fatal(err)
			}
			direct, err := Apply(source, combined)
			if err != nil {
				t.Fatal(err)
			}
			if sequential.Bounds() != direct.Bounds() || !bytes.Equal(sequential.(*image.RGBA).Pix, direct.(*image.RGBA).Pix) {
				t.Fatalf("composition mismatch before=%d after=%d", before, after)
			}
		}
	}
}

func TestSignedRestrictions(t *testing.T) {
	p := Policy{Width: 4, Height: 2, Tile: 2}
	params, err := Setup(p)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cropauth.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	source := sample(4, 2)
	data, err := Issue(p, source, signer)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().Bytes()
	identity := p.Identity()
	proof, err := Prove(params, identity, pub, data, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(p, identity, pub, params.VK, data.Certificate, proof, source); err != nil {
		t.Fatal(err)
	}
	for _, tr := range []Transform{{Width: 2, Height: 2}, {Width: 4, Height: 2, Rotation: 1}} {
		if err := p.ValidateTransform(tr); err == nil {
			t.Fatal("accepted forbidden operation")
		}
	}
	// Bypass policy checks and supply a cropped witness to the restricted circuit.
	permissive := p
	permissive.AllowCrop = true
	tr := Transform{Width: 2, Height: 2}
	out, _ := Apply(source, tr)
	a, err := assignment(permissive, tr, pub, data.Certificate, out)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range p.header() {
		a.Header[i] = v
	}
	for i, v := range data.Hashes {
		a.Source[i] = "0x" + v
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groth16.Prove(params.CS, params.PK, w); err == nil {
		t.Fatal("circuit accepted forbidden crop")
	}
}
