package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"photoproof/cropauth"
)

type authority struct {
	Policy    cropauth.Policy `json:"policy"`
	PublicKey []byte          `json:"signer_public_key"`
	VKHash    string          `json:"verifying_key_sha256"`
}

func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func serialized(v io.WriterTo) ([]byte, error) {
	var b bytes.Buffer
	_, err := v.WriteTo(&b)
	return b.Bytes(), err
}
func readProof(path string) (groth16.Proof, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := groth16.NewProof(ecc.BN254)
	r := bytes.NewReader(b)
	if _, err := p.ReadFrom(r); err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, errors.New("unexpected trailing proof bytes")
	}
	return p, nil
}
func loadAuthority(dir string) (authority, groth16.VerifyingKey, error) {
	var a authority
	if err := readJSON(filepath.Join(dir, "authority.json"), &a); err != nil {
		return a, nil, err
	}
	if err := a.Policy.Validate(); err != nil {
		return a, nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "verifying-key.bin"))
	if err != nil {
		return a, nil, err
	}
	d := sha256.Sum256(b)
	if hex.EncodeToString(d[:]) != a.VKHash {
		return a, nil, errors.New("verifying key differs from trusted manifest")
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	r := bytes.NewReader(b)
	if _, err := vk.ReadFrom(r); err != nil {
		return a, nil, err
	}
	if r.Len() != 0 {
		return a, nil, errors.New("unexpected trailing key bytes")
	}
	return a, vk, nil
}

func verify(trusted, certPath, proofPath, imagePath string) error {
	a, vk, err := loadAuthority(trusted)
	if err != nil {
		return err
	}
	var cert cropauth.Certificate
	if err := readJSON(certPath, &cert); err != nil {
		return err
	}
	proof, err := readProof(proofPath)
	if err != nil {
		return err
	}
	im, err := cropauth.ReadImage(imagePath)
	if err != nil {
		return err
	}
	return cropauth.Verify(a.Policy, a.PublicKey, vk, cert, proof, im)
}

func experiment(input, out string, tile, x, y, w, h int) error {
	source, err := cropauth.ReadImage(input)
	if err != nil {
		return err
	}
	b := source.Bounds()
	if x < 0 {
		x = b.Dx() / 4
	}
	if w < 0 {
		w = b.Dx() / 2
	}
	if h < 0 {
		h = b.Dy()
	}
	p := cropauth.Policy{SourceWidth: b.Dx(), SourceHeight: b.Dy(), Tile: tile, X: x, Y: y, Width: w, Height: h}
	if err := p.Validate(); err != nil {
		return err
	}
	// Refuse to overwrite existing experimental evidence.
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	trusted := filepath.Join(out, "trusted")
	if err := os.Mkdir(trusted, 0755); err != nil {
		return err
	}
	cropped := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(cropped, cropped.Bounds(), source, b.Min.Add(image.Pt(x, y)), draw.Src)
	if err := cropauth.SavePNG(filepath.Join(out, "crop.png"), cropped); err != nil {
		return err
	}
	changed := image.NewRGBA(cropped.Bounds())
	draw.Draw(changed, changed.Bounds(), cropped, image.Point{}, draw.Src)
	r, g, bl, _ := changed.At(0, 0).RGBA()
	changed.SetRGBA(0, 0, color.RGBA{R: byte(r>>8) ^ 1, G: byte(g >> 8), B: byte(bl >> 8), A: 255})
	if err := cropauth.SavePNG(filepath.Join(out, "one-pixel-changed.png"), changed); err != nil {
		return err
	}
	marked := image.NewRGBA(cropped.Bounds())
	draw.Draw(marked, marked.Bounds(), cropped, image.Point{}, draw.Src)
	draw.Draw(marked, image.Rect(0, 0, 80, 80).Intersect(marked.Bounds()), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	if err := cropauth.SavePNG(filepath.Join(out, "marked.png"), marked); err != nil {
		return err
	}
	wrong := image.NewRGBA(cropped.Bounds())
	wrongX := 0
	if x == 0 && x+w < b.Dx() {
		wrongX = tile
	}
	draw.Draw(wrong, wrong.Bounds(), source, b.Min.Add(image.Pt(wrongX, y)), draw.Src)
	if err := cropauth.SavePNG(filepath.Join(out, "wrong-region.png"), wrong); err != nil {
		return err
	}
	start := time.Now()
	params, err := cropauth.Setup(p)
	if err != nil {
		return err
	}
	setupMS := float64(time.Since(start).Microseconds()) / 1000
	fmt.Printf("SETUP constraints=%d compile_and_setup_ms=%.3f\n", params.CS.GetNbConstraints(), setupMS)
	signer, err := cropauth.NewSigner()
	if err != nil {
		return err
	}
	pub := signer.Public().Bytes()
	cert, err := cropauth.SignOriginal(p, source, signer)
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(out, "certificate.json"), cert); err != nil {
		return err
	}
	vkBytes, err := serialized(params.VK)
	if err != nil {
		return err
	}
	vkHash := sha256.Sum256(vkBytes)
	if err := os.WriteFile(filepath.Join(trusted, "verifying-key.bin"), vkBytes, 0644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(trusted, "authority.json"), authority{p, pub, hex.EncodeToString(vkHash[:])}); err != nil {
		return err
	}
	start = time.Now()
	proof, err := cropauth.Prove(params, pub, cert, source, cropped)
	if err != nil {
		return err
	}
	proveMS := float64(time.Since(start).Microseconds()) / 1000
	proofBytes, err := serialized(proof)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "proof.bin"), proofBytes, 0644); err != nil {
		return err
	}
	fmt.Printf("PROVE total_prove_ms=%.3f proof_bytes=%d\n", proveMS, len(proofBytes))
	type result struct {
		Name     string  `json:"name"`
		Accepted bool    `json:"accepted"`
		Expected bool    `json:"expected"`
		MS       float64 `json:"verify_ms"`
		Reason   string  `json:"reason,omitempty"`
	}
	var results []result
	certPath, proofPath := filepath.Join(out, "certificate.json"), filepath.Join(out, "proof.bin")
	for _, c := range []struct {
		name, path string
		expected   bool
	}{
		{"authorized_crop", filepath.Join(out, "crop.png"), true},
		{"one_pixel_changed", filepath.Join(out, "one-pixel-changed.png"), false},
		{"red_square_added", filepath.Join(out, "marked.png"), false},
		{"wrong_crop_region", filepath.Join(out, "wrong-region.png"), false},
		{"original_wrong_dimensions", input, false},
	} {
		start = time.Now()
		err := verify(trusted, certPath, proofPath, c.path)
		ms := float64(time.Since(start).Microseconds()) / 1000
		r := result{Name: c.name, Accepted: err == nil, Expected: c.expected, MS: ms}
		if err != nil {
			r.Reason = err.Error()
		}
		results = append(results, r)
		fmt.Printf("RESULT name=%s accepted=%v expected=%v verify_ms=%.3f\n", r.Name, r.Accepted, r.Expected, r.MS)
	}
	// Also try generating a NEW proof for an unauthorized output.
	_, badErr := cropauth.Prove(params, pub, cert, source, changed)
	results = append(results, result{Name: "prove_changed_pixels", Accepted: badErr == nil, Expected: false})
	if badErr != nil {
		results[len(results)-1].Reason = badErr.Error()
	}
	fmt.Printf("RESULT name=prove_changed_pixels accepted=%v expected=false\n", badErr == nil)
	inputBytes, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	inputHash := sha256.Sum256(inputBytes)
	summary := struct {
		Policy      cropauth.Policy `json:"policy"`
		InputSHA256 string          `json:"input_sha256"`
		Constraints int             `json:"constraints"`
		SetupMS     float64         `json:"compile_and_setup_ms"`
		ProveMS     float64         `json:"total_prove_ms"`
		ProofBytes  int             `json:"proof_bytes"`
		Results     []result        `json:"results"`
	}{p, hex.EncodeToString(inputHash[:]), params.CS.GetNbConstraints(), setupMS, proveMS, len(proofBytes), results}
	if err := writeJSON(filepath.Join(out, "results.json"), summary); err != nil {
		return err
	}
	for _, r := range results {
		if r.Accepted != r.Expected {
			return fmt.Errorf("unexpected result: %s", r.Name)
		}
	}
	fmt.Println("ALL CHECKS MATCH EXPECTATIONS")
	return nil
}

func main() {
	mode := flag.String("mode", "experiment", "experiment or verify")
	input := flag.String("input", "../1.JPG", "original image")
	out := flag.String("out", "../experiment-results/crop-auth", "new output directory")
	tile := flag.Int("tile", 90, "tile edge in pixels")
	x := flag.Int("x", -1, "permitted crop x; default is one quarter of source width")
	y := flag.Int("y", 0, "permitted crop y")
	w := flag.Int("width", -1, "permitted crop width; default is half source width")
	h := flag.Int("height", -1, "permitted crop height; default is full height")
	trusted := flag.String("trusted", "", "trusted authority directory (verify mode)")
	cert := flag.String("certificate", "", "certificate JSON (verify mode)")
	proof := flag.String("proof", "", "proof binary (verify mode)")
	im := flag.String("image", "", "received image (verify mode)")
	flag.Parse()
	var err error
	switch *mode {
	case "experiment":
		err = experiment(*input, *out, *tile, *x, *y, *w, *h)
	case "verify":
		err = verify(*trusted, *cert, *proof, *im)
		if err == nil {
			fmt.Println("ACCEPT: image matches the signed crop policy")
		}
	default:
		err = errors.New("unknown mode")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "REJECT:", err)
		os.Exit(1)
	}
}
