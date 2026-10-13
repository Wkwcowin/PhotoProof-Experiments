package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"photoproof/pixelauth"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "REJECT:", err)
		os.Exit(1)
	}
}
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
func readImage(path string) (image.Image, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	im, _, e := image.Decode(f)
	return im, e
}
func newDir(path string) error {
	if path == "" {
		return errors.New("output directory is required")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		return fmt.Errorf("output already exists or inaccessible: %s", path)
	}
	return os.MkdirAll(path, 0755)
}
func loadTrust(path string) (*pixelauth.Basis, pixelauth.Trust, error) {
	var t pixelauth.Trust
	if e := readJSON(filepath.Join(path, "authority.json"), &t); e != nil {
		return nil, t, e
	}
	data, e := os.ReadFile(filepath.Join(path, "generators.bin"))
	if e != nil {
		return nil, t, e
	}
	b, e := pixelauth.DecodeTrustedBasis(data, t.Pixels, t.GeneratorDigest)
	return b, t, e
}
func loadBundle(path string) (pixelauth.Chain, [][]byte, error) {
	var c pixelauth.Chain
	if e := readJSON(filepath.Join(path, "manifest.json"), &c); e != nil {
		return c, nil, e
	}
	if len(c.Steps) > 64 {
		return c, nil, errors.New("too many steps")
	}
	p := make([][]byte, len(c.Steps))
	for i := range p {
		var e error
		p[i], e = os.ReadFile(filepath.Join(path, fmt.Sprintf("step-%03d.bin", i+1)))
		if e != nil {
			return c, nil, e
		}
	}
	return c, p, nil
}
func run() error {
	mode := flag.String("mode", "verify", "init, edit, verify")
	root := flag.String("workspace", "", "source workspace")
	trusted := flag.String("trusted", "", "independently trusted authority directory")
	input := flag.String("input", "", "image path")
	prior := flag.String("prior", "", "prior edited bundle")
	out := flag.String("out", "", "new edited bundle")
	bundle := flag.String("bundle", "", "bundle to verify")
	x := flag.Int("x", 0, "crop x")
	y := flag.Int("y", 0, "crop y")
	w := flag.Int("width", 0, "crop width")
	h := flag.Int("height", 0, "crop height")
	rw := flag.Int("resize-width", 0, "nearest neighbor output width")
	rh := flag.Int("resize-height", 0, "nearest neighbor output height")
	rot := flag.Int("rotate", 0, "clockwise degrees: 0,90,180,270")
	flag.Parse()
	start := time.Now()
	if *mode == "init" {
		im, e := readImage(*input)
		if e != nil {
			return e
		}
		if _, e = pixelauth.Pixels(im); e != nil {
			return e
		}
		if e = newDir(*root); e != nil {
			return e
		}
		td := filepath.Join(*root, "trusted")
		if e = os.Mkdir(td, 0755); e != nil {
			return e
		}
		n := im.Bounds().Dx() * im.Bounds().Dy()
		fmt.Printf("Generating %d independent generators...\n", n)
		bs := time.Now()
		b, e := pixelauth.GenerateBasis(n)
		if e != nil {
			return e
		}
		genSeconds := time.Since(bs).Seconds()
		data, e := b.Encode()
		if e != nil {
			return e
		}
		digest := pixelauth.Digest(data)
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		cert, opening, e := pixelauth.Issue(b, digest, im, pixelauth.Policy{AllowCrop: true, AllowResize: true, AllowRotate: true}, key)
		if e != nil {
			return e
		}
		t := pixelauth.Trust{PublicKey: pub, GeneratorDigest: digest, CertificateDigest: cert.Digest(), Pixels: n}
		if e = os.WriteFile(filepath.Join(td, "generators.bin"), data, 0644); e != nil {
			return e
		}
		if e = writeJSON(filepath.Join(td, "authority.json"), t); e != nil {
			return e
		}
		if e = writeJSON(filepath.Join(*root, "source-certificate.json"), cert); e != nil {
			return e
		}
		if e = os.WriteFile(filepath.Join(*root, "source-opening.bin"), opening, 0600); e != nil {
			return e
		}
		raw, e := os.ReadFile(*input)
		if e != nil {
			return e
		}
		stats := map[string]any{"source_sha256": pixelauth.Digest(raw), "width": cert.Width, "height": cert.Height, "generator_seconds": genSeconds, "generator_bytes": len(data), "total_seconds": time.Since(start).Seconds()}
		if e = writeJSON(filepath.Join(*root, "initialization.json"), stats); e != nil {
			return e
		}
		fmt.Println("INIT OK", time.Since(start))
		return nil
	}
	if *trusted == "" && *root != "" {
		*trusted = filepath.Join(*root, "trusted")
	}
	bs := time.Now()
	b, t, e := loadTrust(*trusted)
	if e != nil {
		return e
	}
	loadSeconds := time.Since(bs).Seconds()
	if *mode == "verify" {
		c, p, e := loadBundle(*bundle)
		if e != nil {
			return e
		}
		if *input == "" {
			*input = filepath.Join(*bundle, "image.png")
		}
		im, e := readImage(*input)
		if e != nil {
			return e
		}
		vs := time.Now()
		if e = pixelauth.VerifyChain(b, t, c, p, im); e != nil {
			return e
		}
		fmt.Printf("ACCEPT steps=%d verify_seconds=%.6f total_seconds=%.6f\n", len(p), time.Since(vs).Seconds(), time.Since(start).Seconds())
		return nil
	}
	if *mode != "edit" {
		return errors.New("unknown mode")
	}
	var c pixelauth.Chain
	var proofs [][]byte
	if *prior != "" {
		c, proofs, e = loadBundle(*prior)
		if e != nil {
			return e
		}
		if *input == "" {
			*input = filepath.Join(*prior, "image.png")
		}
	} else {
		c.Version = 1
		if e = readJSON(filepath.Join(*root, "source-certificate.json"), &c.Certificate); e != nil {
			return e
		}
		c.FinalOpening, e = os.ReadFile(filepath.Join(*root, "source-opening.bin"))
		if e != nil {
			return e
		}
	}
	im, e := readImage(*input)
	if e != nil {
		return e
	}
	vs := time.Now()
	if e = pixelauth.VerifyChain(b, t, c, proofs, im); e != nil {
		return fmt.Errorf("input verification: %w", e)
	}
	priorSeconds := time.Since(vs).Seconds()
	state, e := pixelauth.ChainState(c)
	if e != nil {
		return e
	}
	if *w == 0 {
		*w = state.Width - *x
	}
	if *h == 0 {
		*h = state.Height - *y
	}
	if *rw == 0 {
		*rw = *w
	}
	if *rh == 0 {
		*rh = *h
	}
	if *rot < 0 || *rot > 270 || *rot%90 != 0 {
		return errors.New("rotation must be 0,90,180,270")
	}
	op := pixelauth.Operation{X: *x, Y: *y, Width: *w, Height: *h, ResizeWidth: *rw, ResizeHeight: *rh, Rotation: *rot / 90}
	edited, e := pixelauth.Apply(im, op, c.Certificate.Policy)
	if e != nil {
		return e
	}
	ps := time.Now()
	step, proof, opening, e := pixelauth.ProveStep(b, c.Certificate, c.Steps, state, im, edited, c.FinalOpening, op)
	if e != nil {
		return e
	}
	proveSeconds := time.Since(ps).Seconds()
	c.Steps = append(c.Steps, step)
	c.FinalOpening = opening
	proofs = append(proofs, proof)
	vs = time.Now()
	if e = pixelauth.VerifyChain(b, t, c, proofs, edited); e != nil {
		return e
	}
	verifySeconds := time.Since(vs).Seconds()
	if e = newDir(*out); e != nil {
		return e
	}
	f, e := os.Create(filepath.Join(*out, "image.png"))
	if e != nil {
		return e
	}
	e = png.Encode(f, edited)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = writeJSON(filepath.Join(*out, "manifest.json"), c); e != nil {
		return e
	}
	totalBytes := 0
	for i, p := range proofs {
		totalBytes += len(p)
		if e = os.WriteFile(filepath.Join(*out, fmt.Sprintf("step-%03d.bin", i+1)), p, 0644); e != nil {
			return e
		}
	}
	stats := map[string]any{"steps": len(proofs), "width": edited.Bounds().Dx(), "height": edited.Bounds().Dy(), "basis_load_seconds": loadSeconds, "prior_verify_seconds": priorSeconds, "prove_seconds": proveSeconds, "chain_verify_seconds": verifySeconds, "new_proof_bytes": len(proof), "total_proof_bytes": totalBytes, "total_seconds": time.Since(start).Seconds()}
	if e = writeJSON(filepath.Join(*out, "results.json"), stats); e != nil {
		return e
	}
	fmt.Printf("EDIT ACCEPT steps=%d proof_bytes=%d total_seconds=%.6f\n", len(proofs), totalBytes, time.Since(start).Seconds())
	return nil
}
