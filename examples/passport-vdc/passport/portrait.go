package passport

import (
	"bytes"
	"image"
	"image/jpeg"
	"slices"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/mrjoshuak/go-jpeg2000"
)

// maxPortraitSide bounds each side of a decoded face image. ICAO 9303
// portraits are a few hundred pixels a side; anything far larger isn't
// a passport photo, and isn't decoded.
const maxPortraitSide = 2048

// portraitJPEGQuality is the quality a JPEG 2000 portrait is re-encoded
// at.
const portraitJPEGQuality = 90

// portraitJPEG returns the passport's first DG2 face image as JPEG:
// unchanged when the passport stores JPEG, converted when it stores
// JPEG 2000, which browsers and most verifiers can't display. It
// returns nil when there's no usable face image. The portrait is a
// displayable copy for convenience; the raw, country-signed DG2 is
// always carried alongside it.
func portraitJPEG(faces []document.ImageData) []byte {
	if len(faces) == 0 {
		return nil
	}
	face := faces[0].Data
	switch format, _ := utils.DetectImageFormat(face); format {
	case utils.ImageFormatJPEG:
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(face))
		if err != nil || !portraitSized(cfg.Width, cfg.Height) {
			return nil
		}
		return slices.Clone(face)
	case utils.ImageFormatJPEG2000:
		return jpeg2000ToJPEG(face)
	default:
		return nil
	}
}

func jpeg2000ToJPEG(face []byte) []byte {
	// The header is checked first, so an oversized image is refused
	// before its pixels are decoded.
	meta, err := jpeg2000.DecodeMetadata(bytes.NewReader(face))
	if err != nil || !portraitSized(meta.Width, meta.Height) {
		return nil
	}
	img, err := jpeg2000.Decode(bytes.NewReader(face))
	if err != nil || !portraitSized(img.Bounds().Dx(), img.Bounds().Dy()) {
		return nil
	}
	return encodeJPEG(img)
}

func encodeJPEG(img image.Image) []byte {
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: portraitJPEGQuality}); err != nil {
		return nil
	}
	return out.Bytes()
}

func portraitSized(width, height int) bool {
	return width > 0 && height > 0 && width <= maxPortraitSide && height <= maxPortraitSide
}
