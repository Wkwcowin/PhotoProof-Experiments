package main

import (
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"photoproof/pixelauth"
	"testing"
	"time"
)

func TestRealPhotoChain(t *testing.T) {
	root := os.Getenv("PHOTOPROOF_PIXEL_WORKSPACE")
	if root == "" {
		t.Skip("set PHOTOPROOF_PIXEL_WORKSPACE to opt in")
	}
	b, trust, e := loadTrust(filepath.Join(root, "trusted"))
	if e != nil {
		t.Fatal(e)
	}
	c, p, e := loadBundle(filepath.Join(root, "edit-b"))
	if e != nil {
		t.Fatal(e)
	}
	im, e := readImage(filepath.Join(root, "edit-b", "image.png"))
	if e != nil {
		t.Fatal(e)
	}
	type check struct {
		Name           string  `json:"name"`
		Accepted       bool    `json:"accepted"`
		ExpectedAccept bool    `json:"expected_accept"`
		Seconds        float64 `json:"seconds"`
		Error          string  `json:"error,omitempty"`
	}
	results := []check{}
	verify := func(name string, chain pixelauth.Chain, proofs [][]byte, img image.Image, want bool) {
		t.Helper()
		s := time.Now()
		err := pixelauth.VerifyChain(b, trust, chain, proofs, img)
		r := check{Name: name, Accepted: err == nil, ExpectedAccept: want, Seconds: time.Since(s).Seconds()}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
		if (err == nil) != want {
			t.Errorf("%s: %v", name, err)
		}
		t.Logf("%s accepted=%v seconds=%.3f error=%v", name, err == nil, r.Seconds, err)
	}
	clone := func() pixelauth.Chain {
		data, _ := json.Marshal(c)
		var out pixelauth.Chain
		if err := json.Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	verify("valid_two_step_chain", c, p, im, true)
	a, ap, e := loadBundle(filepath.Join(root, "edit-a"))
	if e != nil {
		t.Fatal(e)
	}
	ai, e := readImage(filepath.Join(root, "edit-a", "image.png"))
	if e != nil {
		t.Fatal(e)
	}
	verify("valid_first_step", a, ap, ai, true)
	changed := image.NewRGBA(im.Bounds())
	draw.Draw(changed, changed.Bounds(), im, im.Bounds().Min, draw.Src)
	old := changed.RGBAAt(0, 0)
	old.R ^= 1
	changed.SetRGBA(0, 0, old)
	verify("one_pixel_modified", c, p, changed, false)
	f, e := os.Create(filepath.Join(root, "one-pixel-tampered.png"))
	if e != nil {
		t.Fatal(e)
	}
	if e = png.Encode(f, changed); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	draw.Draw(changed, image.Rect(10, 10, 30, 30), image.NewUniform(color.RGBA{255, 0, 0, 255}), image.Point{}, draw.Src)
	verify("red_block_added", c, p, changed, false)
	altered := clone()
	altered.Steps[0].Operation.X++
	verify("earlier_crop_changed", altered, p, im, false)
	altered = clone()
	altered.Steps[0].Operation.Width--
	verify("earlier_resize_sampling_changed", altered, p, im, false)
	altered = clone()
	altered.Steps[0].Operation.Rotation = 3
	verify("earlier_rotation_changed", altered, p, im, false)
	altered = clone()
	pp := append([][]byte(nil), p...)
	pp[0] = append([]byte(nil), p[0]...)
	pp[0][len(pp[0])-1] ^= 1
	altered.Steps[0].ProofDigest = pixelauth.Digest(pp[0])
	verify("proof_response_changed_and_hash_updated", altered, pp, im, false)
	pp = append([][]byte(nil), p...)
	pp[0] = pp[0][:len(pp[0])-1]
	verify("truncated_proof", c, pp, im, false)
	altered = clone()
	altered.FinalOpening[0] ^= 1
	verify("final_opening_changed", altered, p, im, false)
	// The editor runs this identical check before any new proof is created.
	verify("tampered_input_rejected_before_next_edit", c, p, changed, false)
	if e = writeJSON(filepath.Join(root, "checks.json"), results); e != nil {
		t.Fatal(e)
	}
}
