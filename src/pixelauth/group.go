package pixelauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const MaxPixels = 2_000_000

var generatorDST = []byte("PhotoProof-pixel-relation-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_")

type Basis struct {
	Points []bls.G1Affine
	Blind  bls.G1Affine
}

// Independent hash-to-curve generators are essential: known discrete-log
// relations between the bases would destroy vector-commitment binding.
func GenerateBasis(n int) (*Basis, error) {
	if n <= 0 || n > MaxPixels {
		return nil, errors.New("invalid basis size")
	}
	points := make([]bls.G1Affine, n)
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			for i := k; i < n; i += workers {
				var index [8]byte
				binary.BigEndian.PutUint64(index[:], uint64(i))
				point, err := bls.HashToG1(append([]byte("pixel/"), index[:]...), generatorDST)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				points[i] = point
			}
		}(worker)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	h, err := bls.HashToG1([]byte("independent-blinding-generator"), generatorDST)
	if err != nil {
		return nil, err
	}
	return &Basis{points, h}, nil
}

func (b *Basis) Encode() ([]byte, error) {
	var buf bytes.Buffer
	err := bls.NewEncoder(&buf, bls.RawEncoding()).Encode(b.Points)
	return buf.Bytes(), err
}
func Digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// DecodeTrustedBasis only accepts a byte-for-byte cache pinned by the trusted
// authority. It must NEVER be used with a digest supplied by an untrusted editor.
// The cache was generated with HashToG1, so repeated subgroup checks are omitted
// here; all externally supplied proof/commitment points still get full checks.
func DecodeTrustedBasis(data []byte, n int, trustedDigest string) (*Basis, error) {
	if n <= 0 || n > MaxPixels || len(data) != 4+96*n || len(trustedDigest) != 64 || Digest(data) != trustedDigest {
		return nil, errors.New("generator cache does not match trusted parameters")
	}
	if int(binary.BigEndian.Uint32(data[:4])) != n {
		return nil, errors.New("generator count mismatch")
	}
	var points []bls.G1Affine
	r := bytes.NewReader(data)
	if err := bls.NewDecoder(r, bls.NoSubgroupChecks()).Decode(&points); err != nil {
		return nil, err
	}
	if r.Len() != 0 || len(points) != n {
		return nil, errors.New("invalid generator cache")
	}
	h, err := bls.HashToG1([]byte("independent-blinding-generator"), generatorDST)
	if err != nil {
		return nil, err
	}
	return &Basis{points, h}, nil
}

func scalarPoint(p *bls.G1Affine, v *fr.Element) bls.G1Affine {
	var n big.Int
	v.BigInt(&n)
	var out bls.G1Affine
	out.ScalarMultiplication(p, &n)
	return out
}
func (b *Basis) Commit(values []fr.Element, blind fr.Element) (bls.G1Affine, error) {
	var out bls.G1Affine
	if len(values) == 0 || len(values) > len(b.Points) {
		return out, errors.New("invalid commitment length")
	}
	if _, err := out.MultiExp(b.Points[:len(values)], values, ecc.MultiExpConfig{}); err != nil {
		return out, err
	}
	h := scalarPoint(&b.Blind, &blind)
	out.Add(&out, &h)
	return out, nil
}

func pointBytes(p bls.G1Affine) []byte { b := p.Bytes(); return append([]byte(nil), b[:]...) }
func parsePoint(b []byte) (bls.G1Affine, error) {
	var p bls.G1Affine
	if len(b) != 48 {
		return p, errors.New("invalid compressed point length")
	}
	n, err := p.SetBytes(b)
	if err != nil {
		return p, err
	}
	if n != 48 {
		return p, errors.New("noncanonical point length")
	}
	return p, nil
}
func parseScalar(b []byte) (fr.Element, error) {
	var v fr.Element
	if len(b) != 32 {
		return v, errors.New("invalid scalar length")
	}
	err := v.SetBytesCanonical(b)
	return v, err
}
func scalarBytes(v fr.Element) []byte   { b := v.Bytes(); return append([]byte(nil), b[:]...) }
func randomScalar() (fr.Element, error) { var v fr.Element; _, err := v.SetRandom(); return v, err }

func validateBasis(b *Basis, n int) error {
	if b == nil || len(b.Points) < n {
		return fmt.Errorf("basis requires %d pixel generators", n)
	}
	return nil
}
