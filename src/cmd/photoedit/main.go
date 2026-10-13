// photoedit separates source signing, editing/proving and standalone verification.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"photoproof/cropauth"
	"photoproof/flexauth"
)

type Authority struct {
	Version   int             `json:"version"`
	Policy    flexauth.Policy `json:"policy"`
	PublicKey []byte          `json:"signer_public_key"`
	VKHash    string          `json:"verifying_key_sha256"`
}
type Manifest struct {
	Version     int                  `json:"version"`
	Certificate cropauth.Certificate `json:"certificate"`
	Transform   flexauth.Transform   `json:"transform"`
}

func writeJSON(path string, v interface{}, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}
func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func encode(v io.WriterTo) ([]byte, error) {
	var b bytes.Buffer
	_, err := v.WriteTo(&b)
	return b.Bytes(), err
}
func decodeFile(path string, v io.ReaderFrom) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	r := bytes.NewReader(b)
	if _, err := v.ReadFrom(r); err != nil {
		return err
	}
	if r.Len() != 0 {
		return errors.New("unexpected trailing data")
	}
	return nil
}
func hashHex(b []byte) string          { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func milliseconds(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }

func loadAuthority(dir string) (Authority, groth16.VerifyingKey, error) {
	var a Authority
	if err := readJSON(filepath.Join(dir, "authority.json"), &a); err != nil {
		return a, nil, err
	}
	if a.Version != 2 {
		return a, nil, errors.New("unsupported authority version")
	}
	if err := a.Policy.Validate(); err != nil {
		return a, nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "verifying-key.bin"))
	if err != nil {
		return a, nil, err
	}
	if hashHex(b) != a.VKHash {
		return a, nil, errors.New("verifying key differs from trusted manifest")
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	r := bytes.NewReader(b)
	if _, err := vk.ReadFrom(r); err != nil {
		return a, nil, err
	}
	if r.Len() != 0 {
		return a, nil, errors.New("trailing key bytes")
	}
	return a, vk, nil
}
func loadBundle(dir string) (Manifest, groth16.Proof, error) {
	var m Manifest
	if err := readJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return m, nil, err
	}
	if m.Version != 2 {
		return m, nil, errors.New("unsupported proof bundle version")
	}
	proof := groth16.NewProof(ecc.BN254)
	if err := decodeFile(filepath.Join(dir, "proof.bin"), proof); err != nil {
		return m, nil, err
	}
	return m, proof, nil
}
func verify(trusted, bundle, imagePath string) error {
	a, vk, err := loadAuthority(trusted)
	if err != nil {
		return err
	}
	m, proof, err := loadBundle(bundle)
	if err != nil {
		return err
	}
	if imagePath == "" {
		imagePath = filepath.Join(bundle, "image.png")
	}
	im, err := cropauth.ReadImage(imagePath)
	if err != nil {
		return err
	}
	return flexauth.Verify(a.Policy, m.Transform, a.PublicKey, vk, m.Certificate, proof, im)
}

func initialize(input, root string, tile int, crop, rotate bool) error {
	im, err := cropauth.ReadImage(input)
	if err != nil {
		return err
	}
	p := flexauth.Policy{Width: im.Bounds().Dx(), Height: im.Bounds().Dy(), Tile: tile, AllowCrop: crop, AllowRotate: rotate}
	if err := p.Validate(); err != nil {
		return err
	}
	// Every run has a new directory: previous results cannot be silently overwritten.
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	trusted := filepath.Join(root, "trusted")
	if err := os.Mkdir(trusted, 0755); err != nil {
		return err
	}
	start := time.Now()
	params, err := flexauth.Setup(p)
	if err != nil {
		return err
	}
	setupMS := milliseconds(start)
	signer, err := cropauth.NewSigner()
	if err != nil {
		return err
	}
	start = time.Now()
	data, err := flexauth.Issue(p, im, signer)
	if err != nil {
		return err
	}
	signMS := milliseconds(start)
	pk, err := encode(params.PK)
	if err != nil {
		return err
	}
	vk, err := encode(params.VK)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "proving-key.bin"), pk, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(trusted, "verifying-key.bin"), vk, 0644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(trusted, "authority.json"), Authority{2, p, signer.Public().Bytes(), hashHex(vk)}, 0644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(root, "editor-data.json"), data, 0600); err != nil {
		return err
	}
	sourceBytes, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	summary := map[string]interface{}{"source_file_sha256": hashHex(sourceBytes), "constraints": params.CS.GetNbConstraints(), "compile_and_setup_ms": setupMS, "source_hash_and_sign_ms": signMS, "source_commitment": hex.EncodeToString(data.Certificate.Commitment), "policy": p}
	if err := writeJSON(filepath.Join(root, "initialization.json"), summary, 0644); err != nil {
		return err
	}
	fmt.Printf("INITIALIZED constraints=%d setup_ms=%.3f sign_ms=%.3f\n", params.CS.GetNbConstraints(), setupMS, signMS)
	return nil
}

func edit(root, input, prior, out string, request flexauth.Transform) error {
	start := time.Now()
	a, vk, err := loadAuthority(filepath.Join(root, "trusted"))
	if err != nil {
		return err
	}
	var data flexauth.EditorData
	if err := readJSON(filepath.Join(root, "editor-data.json"), &data); err != nil {
		return err
	}
	previous := a.Policy.Identity()
	if prior != "" {
		if input == "" {
			input = filepath.Join(prior, "image.png")
		}
		if err := verify(filepath.Join(root, "trusted"), prior, input); err != nil {
			return fmt.Errorf("previous edit is invalid: %w", err)
		}
		m, _, err := loadBundle(prior)
		if err != nil {
			return err
		}
		if !bytes.Equal(m.Certificate.Commitment, data.Certificate.Commitment) || !bytes.Equal(m.Certificate.Signature, data.Certificate.Signature) {
			return errors.New("previous edit belongs to a different source certificate")
		}
		previous = m.Transform
	}
	im, err := cropauth.ReadImage(input)
	if err != nil {
		return err
	}
	if request.Width == 0 {
		request.Width = im.Bounds().Dx() - request.X
	}
	if request.Height == 0 {
		request.Height = im.Bounds().Dy() - request.Y
	}
	combined, err := flexauth.Compose(a.Policy, previous, request)
	if err != nil {
		return err
	}
	output, err := flexauth.Apply(im, request)
	if err != nil {
		return err
	}
	cs, err := flexauth.Compile(a.Policy)
	if err != nil {
		return err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := decodeFile(filepath.Join(root, "proving-key.bin"), pk); err != nil {
		return err
	}
	params := &flexauth.Parameters{Policy: a.Policy, CS: cs, PK: pk, VK: vk}
	prepareMS := milliseconds(start)
	start = time.Now()
	proof, err := flexauth.Prove(params, combined, a.PublicKey, data, output)
	if err != nil {
		return err
	}
	proveMS := milliseconds(start)
	// Store only a proof that verifies against the actual output image.
	if err := flexauth.Verify(a.Policy, combined, a.PublicKey, vk, data.Certificate, proof, output); err != nil {
		return err
	}
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	if err := cropauth.SavePNG(filepath.Join(out, "image.png"), output); err != nil {
		return err
	}
	proofBytes, err := encode(proof)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "proof.bin"), proofBytes, 0644); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(out, "manifest.json"), Manifest{2, data.Certificate, combined}, 0644); err != nil {
		return err
	}
	start = time.Now()
	if err := verify(filepath.Join(root, "trusted"), out, ""); err != nil {
		return err
	}
	verifyMS := milliseconds(start)
	summary := map[string]interface{}{"transform": combined, "output_width": output.Bounds().Dx(), "output_height": output.Bounds().Dy(), "source_commitment": hex.EncodeToString(data.Certificate.Commitment), "prepare_ms": prepareMS, "prove_ms": proveMS, "verify_from_files_ms": verifyMS, "proof_bytes": len(proofBytes)}
	if err := writeJSON(filepath.Join(out, "result.json"), summary, 0644); err != nil {
		return err
	}
	fmt.Printf("EDIT ACCEPTED size=%dx%d rotation=%d proof_bytes=%d prove_ms=%.3f verify_ms=%.3f\n", output.Bounds().Dx(), output.Bounds().Dy(), combined.Rotation*90, len(proofBytes), proveMS, verifyMS)
	return nil
}

func run() error {
	mode := flag.String("mode", "verify", "init, edit or verify")
	root := flag.String("workspace", "", "signing/proving workspace")
	input := flag.String("input", "", "source/current image")
	out := flag.String("out", "", "new proof bundle directory")
	prior := flag.String("prior", "", "previous verified bundle for another edit")
	trusted := flag.String("trusted", "", "pretrusted authority directory; verify mode never needs the original")
	bundle := flag.String("bundle", "", "public proof bundle to verify")
	tile := flag.Int("tile", 90, "source tile size")
	allowCrop := flag.Bool("allow-crop", true, "signer allows editor-selected crops")
	allowRotate := flag.Bool("allow-rotate", true, "signer allows quarter-turn rotations")
	x := flag.Int("x", 0, "crop x in current image pixels")
	y := flag.Int("y", 0, "crop y")
	w := flag.Int("width", 0, "crop width; 0 keeps remaining width")
	h := flag.Int("height", 0, "crop height; 0 keeps remaining height")
	rotation := flag.Int("rotate", 0, "clockwise rotation: 0, 90, 180, 270")
	flag.Parse()
	switch *mode {
	case "init":
		return initialize(*input, *root, *tile, *allowCrop, *allowRotate)
	case "edit":
		if *rotation < 0 || *rotation > 270 || *rotation%90 != 0 {
			return errors.New("rotation must be 0, 90, 180 or 270")
		}
		return edit(*root, *input, *prior, *out, flexauth.Transform{X: *x, Y: *y, Width: *w, Height: *h, Rotation: *rotation / 90})
	case "verify":
		if err := verify(*trusted, *bundle, *input); err != nil {
			return err
		}
		fmt.Println("ACCEPT: image is an allowed crop/rotation of the signed source")
		return nil
	default:
		return errors.New("unknown mode")
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "REJECT:", err)
		os.Exit(1)
	}
}
