package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	photo "photoproof/image"
)

// This experiment exercises the original verifier without changing its circuit.
// Accepting an edited image with the original proof is an observed limitation,
// not successful verification of a permitted image transformation.
func TestRealPhotoOriginalVerifier(t *testing.T) {
	input := os.Getenv("PHOTOPROOF_INPUT")
	if input == "" {
		t.Skip("set PHOTOPROOF_INPUT to run the real-photo experiment")
	}
	out := os.Getenv("PHOTOPROOF_OUTPUT")
	if out == "" {
		out = "../experiment-results/real-photo"
	}
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := image.Decode(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	b := decoded.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 2 || h < 2 {
		t.Fatal("image too small")
	}
	original := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(original, original.Bounds(), decoded, b.Min, draw.Src)

	// Keep the centre half of the image width, without rescaling.
	crop := image.NewRGBA(image.Rect(0, 0, w/2, h))
	draw.Draw(crop, crop.Bounds(), original, image.Pt(w/4, 0), draw.Src)
	marked := image.NewRGBA(original.Bounds())
	draw.Draw(marked, marked.Bounds(), original, image.Point{}, draw.Src)
	draw.Draw(marked, image.Rect(0, 0, 80, 80).Intersect(marked.Bounds()),
		&image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)

	convert := func(im image.Image) photo.Image {
		bounds := im.Bounds()
		matrix := make([][]int, bounds.Dy())
		for y := range matrix {
			matrix[y] = make([]int, bounds.Dx()*3)
			for x := 0; x < bounds.Dx(); x++ {
				r, g, b, _ := im.At(x+bounds.Min.X, y+bounds.Min.Y).RGBA()
				matrix[y][3*x], matrix[y][3*x+1], matrix[y][3*x+2] = int(r>>8), int(g>>8), int(b>>8)
			}
		}
		return photo.Image{Matrix: matrix, Metadata: map[string]interface{}{
			"width": bounds.Dx(), "height": bounds.Dy(), "permissibleT": "Identity",
		}}
	}
	savePNG := func(name string, im image.Image) {
		file, err := os.Create(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(file, im); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	savePNG("cropped.png", crop)
	savePNG("marked.png", marked)

	originalPhoto := convert(original)
	pk, vk, signer, err := generator(originalPhoto)
	if err != nil {
		t.Fatal(err)
	}
	var message fr.Element
	message.SetBytes(originalPhoto.EncodeImage())
	sig, err := signer.Sign(message.Marshal(), hash.MIMC_BN254.New())
	if err != nil {
		t.Fatal(err)
	}
	signed := Proof{digital_sig: sig}
	proof, proofVK := proverPCD(signed, originalPhoto, pk)
	if proof.PCD_proof == nil || proof.public_witness == nil {
		t.Fatal("original proof generation failed")
	}

	type result struct {
		Name                      string `json:"name"`
		Width                     int    `json:"width"`
		Height                    int    `json:"height"`
		EncodedSHA256             string `json:"encoded_image_sha256"`
		OriginalSignatureAccepted bool   `json:"original_signature_accepted"`
		OriginalProofAccepted     bool   `json:"original_proof_accepted"`
	}
	var results []result
	for _, c := range []struct {
		name string
		im   image.Image
	}{
		{"original", original}, {"cropped", crop}, {"marked", marked},
	} {
		p := originalPhoto
		if c.name != "original" {
			p = convert(c.im)
		}
		digest := sha256.Sum256(p.EncodeImage())
		sigOK := verifier(vk, p, signed)
		proofOK := verifier(proofVK, p, proof)
		results = append(results, result{c.name, c.im.Bounds().Dx(), c.im.Bounds().Dy(),
			hex.EncodeToString(digest[:]), sigOK, proofOK})
		t.Logf("RESULT image=%s size=%dx%d original_signature=%v original_proof=%v",
			c.name, c.im.Bounds().Dx(), c.im.Bounds().Dy(), sigOK, proofOK)
	}
	inputDigest := sha256.Sum256(raw)
	summary := struct {
		InputSHA256 string   `json:"input_file_sha256"`
		Results     []result `json:"results"`
	}{hex.EncodeToString(inputDigest[:]), results}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "results.json"), append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	// Check the expected observations explicitly, not just the process exit code.
	for i, r := range results {
		if r.OriginalSignatureAccepted != (i == 0) {
			t.Errorf("unexpected signature result for %s", r.Name)
		}
		if !r.OriginalProofAccepted {
			t.Errorf("original verifier unexpectedly rejected %s", r.Name)
		}
		if i > 0 && r.EncodedSHA256 == results[0].EncodedSHA256 {
			t.Errorf("edited image %s is identical to original", r.Name)
		}
	}
}
