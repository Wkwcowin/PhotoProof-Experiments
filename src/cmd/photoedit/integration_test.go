package main

import (
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"os"
	"path/filepath"
	"testing"

	"photoproof/cropauth"
	"photoproof/flexauth"
)

// Opt-in integration experiment using the saved full-resolution proof bundles.
func TestRealImageBundles(t *testing.T) {
	root := os.Getenv("PHOTOPROOF_FLEX_WORKSPACE")
	if root == "" {
		t.Skip("set PHOTOPROOF_FLEX_WORKSPACE to test saved real-image bundles")
	}
	trusted := filepath.Join(root, "trusted")
	a, vk, err := loadAuthority(trusted)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		Name     string `json:"name"`
		Accepted bool   `json:"accepted"`
		Expected bool   `json:"expected"`
		Error    string `json:"error,omitempty"`
	}
	var results []result
	check := func(name string, expected bool, err error) {
		r := result{Name: name, Accepted: err == nil, Expected: expected}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
		t.Logf("%s accepted=%v expected=%v", name, r.Accepted, expected)
		if r.Accepted != expected {
			t.Errorf("unexpected result for %s: %v", name, err)
		}
	}
	for _, name := range []string{"edit-a", "edit-b", "edit-c"} {
		check(name, true, verify(trusted, filepath.Join(root, name), ""))
	}
	out := filepath.Join(root, "negative-cases")
	if err := os.MkdirAll(out, 0755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "edit-a")
	m, proof, err := loadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	im, err := cropauth.ReadImage(filepath.Join(bundle, "image.png"))
	if err != nil {
		t.Fatal(err)
	}
	changed := flexauth.Rotate(im, 0)
	c := changed.RGBAAt(0, 0)
	c.R ^= 1
	changed.SetRGBA(0, 0, c)
	changedPath := filepath.Join(out, "one-pixel-changed.png")
	if err := cropauth.SavePNG(changedPath, changed); err != nil {
		t.Fatal(err)
	}
	check("one_pixel_changed", false, verify(trusted, bundle, changedPath))
	marked := flexauth.Rotate(im, 0)
	draw.Draw(marked, image.Rect(0, 0, 80, 80).Intersect(marked.Bounds()), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	markedPath := filepath.Join(out, "marked.png")
	if err := cropauth.SavePNG(markedPath, marked); err != nil {
		t.Fatal(err)
	}
	check("red_square_added", false, verify(trusted, bundle, markedPath))
	check("substituted_image", false, verify(trusted, bundle, filepath.Join(root, "edit-b", "image.png")))
	wrong := m.Transform
	wrong.X += a.Policy.Tile
	check("modified_crop_coordinates", false, flexauth.Verify(a.Policy, wrong, a.PublicKey, vk, m.Certificate, proof, im))
	wrong = m.Transform
	wrong.Rotation = 3
	check("modified_rotation", false, flexauth.Verify(a.Policy, wrong, a.PublicKey, vk, m.Certificate, proof, im))
	check("tampered_prior_edit", false, edit(root, changedPath, bundle, filepath.Join(out, "should-not-be-created"), flexauth.Transform{Width: im.Bounds().Dx(), Height: im.Bounds().Dy()}))
	// Public-only folder contains no original, source hashes or proving key.
	publicOnly := filepath.Join(root, "verification-only")
	if err := os.MkdirAll(filepath.Join(publicOnly, "trusted"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(publicOnly, "final"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"trusted/authority.json", "trusted/verifying-key.bin", "edit-c/manifest.json", "edit-c/proof.bin", "edit-c/image.png"} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(publicOnly, rel)
		if filepath.Dir(rel) == "edit-c" {
			dest = filepath.Join(publicOnly, "final", filepath.Base(rel))
		}
		if err := os.WriteFile(dest, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	check("public_files_only", true, verify(filepath.Join(publicOnly, "trusted"), filepath.Join(publicOnly, "final"), ""))
	// Decode a deliberately truncated proof through the same public-file parser.
	badDir := filepath.Join(out, "truncated-proof")
	if err := os.MkdirAll(badDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "proof.bin"} {
		b, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "proof.bin" {
			b = b[:len(b)-1]
		}
		if err := os.WriteFile(filepath.Join(badDir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = loadBundle(badDir)
	check("truncated_proof", false, err)
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "checks.json"), append(b, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
