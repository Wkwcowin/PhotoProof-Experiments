package pixelauth

import (
	"errors"
	"image"
	"image/color"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type Policy struct {
	AllowCrop   bool `json:"allow_crop"`
	AllowResize bool `json:"allow_nearest_neighbor_downsize"`
	AllowRotate bool `json:"allow_quarter_turns"`
}

// Operation is crop -> nearest-neighbor downsize -> clockwise quarter turn.
// All coordinates are exact pixel coordinates in the immediately preceding image.
type Operation struct {
	X            int `json:"x"`
	Y            int `json:"y"`
	Width        int `json:"crop_width"`
	Height       int `json:"crop_height"`
	ResizeWidth  int `json:"resize_width"`
	ResizeHeight int `json:"resize_height"`
	Rotation     int `json:"quarter_turns"`
}

func dimensions(w, h int) error {
	if w <= 0 || h <= 0 || w > 16384 || h > 16384 || w*h > MaxPixels {
		return errors.New("invalid or unsupported image dimensions")
	}
	return nil
}
func (o Operation) Size() (int, int) {
	if o.Rotation%2 != 0 {
		return o.ResizeHeight, o.ResizeWidth
	}
	return o.ResizeWidth, o.ResizeHeight
}
func (o Operation) Validate(w, h int, p Policy) error {
	if err := dimensions(w, h); err != nil {
		return err
	}
	if o.X < 0 || o.Y < 0 || o.Width <= 0 || o.Height <= 0 || o.X > w-o.Width || o.Y > h-o.Height {
		return errors.New("crop outside current image")
	}
	if o.ResizeWidth <= 0 || o.ResizeHeight <= 0 || o.ResizeWidth > o.Width || o.ResizeHeight > o.Height {
		return errors.New("only positive nearest-neighbor downsize dimensions are supported")
	}
	if o.Rotation < 0 || o.Rotation > 3 {
		return errors.New("rotation must be a quarter turn")
	}
	if !p.AllowCrop && (o.X != 0 || o.Y != 0 || o.Width != w || o.Height != h) {
		return errors.New("signer does not allow cropping")
	}
	if !p.AllowResize && (o.ResizeWidth != o.Width || o.ResizeHeight != o.Height) {
		return errors.New("signer does not allow downsizing")
	}
	if !p.AllowRotate && o.Rotation != 0 {
		return errors.New("signer does not allow rotation")
	}
	return nil
}

// PixelMap explicitly fixes rounding and rotation. For each output pixel it
// returns the selected input pixel index, including repetitions when applicable.
func (o Operation) PixelMap(w, h int, p Policy) ([]int, error) {
	if err := o.Validate(w, h, p); err != nil {
		return nil, err
	}
	ow, oh := o.Size()
	mapping := make([]int, ow*oh)
	for y := 0; y < oh; y++ {
		for x := 0; x < ow; x++ {
			u, v := x, y
			switch o.Rotation {
			case 1:
				u, v = y, o.ResizeHeight-1-x
			case 2:
				u, v = o.ResizeWidth-1-x, o.ResizeHeight-1-y
			case 3:
				u, v = o.ResizeWidth-1-y, x
			}
			sx := o.X + u*o.Width/o.ResizeWidth
			sy := o.Y + v*o.Height/o.ResizeHeight
			mapping[y*ow+x] = sy*w + sx
		}
	}
	return mapping, nil
}

func Pixels(im image.Image) ([]fr.Element, error) {
	b := im.Bounds()
	if err := dimensions(b.Dx(), b.Dy()); err != nil {
		return nil, err
	}
	values := make([]fr.Element, b.Dx()*b.Dy())
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			r, g, bl, a := im.At(b.Min.X+x, b.Min.Y+y).RGBA()
			if a != 65535 {
				return nil, errors.New("transparent pixels are not supported")
			}
			values[y*b.Dx()+x].SetUint64(uint64(r>>8)<<16 | uint64(g>>8)<<8 | uint64(bl>>8))
		}
	}
	return values, nil
}

func Apply(im image.Image, o Operation, p Policy) (image.Image, error) {
	b := im.Bounds()
	mapping, err := o.PixelMap(b.Dx(), b.Dy(), p)
	if err != nil {
		return nil, err
	}
	w, h := o.Size()
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	for i, j := range mapping {
		r, g, bl, a := im.At(b.Min.X+j%b.Dx(), b.Min.Y+j/b.Dx()).RGBA()
		if a != 65535 {
			return nil, errors.New("transparent pixels are not supported")
		}
		out.SetRGBA(i%w, i/w, color.RGBA{R: byte(r >> 8), G: byte(g >> 8), B: byte(bl >> 8), A: 255})
	}
	return out, nil
}
