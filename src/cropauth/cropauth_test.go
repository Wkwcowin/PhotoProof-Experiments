package cropauth

import (
	"image"
	"image/color"
	"image/draw"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestCropAuthentication(t *testing.T) {
	p := Policy{SourceWidth: 4, SourceHeight: 4, Tile: 2, X: 2, Y: 0, Width: 2, Height: 4}
	source := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			source.SetRGBA(x, y, color.RGBA{R: byte(x * 50), G: byte(y * 50), B: 17, A: 255})
		}
	}
	cropped := image.NewRGBA(image.Rect(0, 0, 2, 4))
	draw.Draw(cropped, cropped.Bounds(), source, image.Pt(2, 0), draw.Src)
	params, err := Setup(p)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.Public().Bytes()
	cert, err := SignOriginal(p, source, signer)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Prove(params, pub, cert, source, cropped)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(p, pub, params.VK, cert, proof, cropped); err != nil {
		t.Fatal(err)
	}

	changed := image.NewRGBA(cropped.Bounds())
	draw.Draw(changed, changed.Bounds(), cropped, image.Point{}, draw.Src)
	changed.SetRGBA(0, 0, color.RGBA{R: 255, A: 255})
	wrongCrop := image.NewRGBA(cropped.Bounds())
	draw.Draw(wrongCrop, wrongCrop.Bounds(), source, image.Point{}, draw.Src)
	for name, im := range map[string]image.Image{"one changed pixel": changed, "wrong crop region": wrongCrop, "wrong dimensions": source} {
		t.Run(name, func(t *testing.T) {
			if err := Verify(p, pub, params.VK, cert, proof, im); err == nil {
				t.Fatal("accepted unauthorized image")
			}
		})
	}
	t.Run("cannot generate proof for edited pixels", func(t *testing.T) {
		if _, err := Prove(params, pub, cert, source, changed); err == nil {
			t.Fatal("proved changed pixels")
		}
	})
	t.Run("changed policy", func(t *testing.T) {
		wrong := p
		wrong.X = 0
		if err := Verify(wrong, pub, params.VK, cert, proof, cropped); err == nil {
			t.Fatal("accepted different policy")
		}
	})
	t.Run("different signer", func(t *testing.T) {
		other, err := NewSigner()
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(p, other.Public().Bytes(), params.VK, cert, proof, cropped); err == nil {
			t.Fatal("accepted different signer")
		}
	})
	t.Run("different signed source", func(t *testing.T) {
		otherSource := image.NewRGBA(source.Bounds())
		draw.Draw(otherSource, otherSource.Bounds(), source, image.Point{}, draw.Src)
		otherSource.SetRGBA(0, 0, color.RGBA{B: 255, A: 255})
		otherCert, err := SignOriginal(p, otherSource, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(p, pub, params.VK, otherCert, proof, cropped); err == nil {
			t.Fatal("accepted certificate for different source")
		}
		if _, err := Prove(params, pub, cert, otherSource, cropped); err == nil {
			t.Fatal("proved different source")
		}
		// Bypass the native source check: the CIRCUIT must reject a false commitment.
		a, err := publicAssignment(p, pub, cert, cropped)
		if err != nil {
			t.Fatal(err)
		}
		limbs, err := sourceHashes(p, otherSource)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range limbs {
			a.Source[i] = v
		}
		w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := groth16.Prove(params.CS, params.PK, w); err == nil {
			t.Fatal("circuit accepted unsigned source")
		}
	})
	t.Run("malformed signature", func(t *testing.T) {
		bad := cert
		bad.Signature = []byte{1}
		if err := Verify(p, pub, params.VK, bad, proof, cropped); err == nil {
			t.Fatal("accepted malformed signature")
		}
	})
	t.Run("transparent pixels", func(t *testing.T) {
		transparent := image.NewRGBA(cropped.Bounds())
		if err := Verify(p, pub, params.VK, cert, proof, transparent); err == nil {
			t.Fatal("accepted transparent output")
		}
	})
}
