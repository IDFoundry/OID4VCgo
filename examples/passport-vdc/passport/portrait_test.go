package passport

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/mrjoshuak/go-jpeg2000"
)

func testFace(width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x80, A: 0xFF})
		}
	}
	return img
}

func encodeTestJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	return b.Bytes()
}

func encodeTestJP2(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg2000.Encode(&b, img, nil); err != nil {
		t.Fatalf("jpeg2000.Encode: %v", err)
	}
	return b.Bytes()
}

func faces(images ...[]byte) []document.ImageData {
	out := make([]document.ImageData, len(images))
	for i, img := range images {
		out[i] = document.ImageData{Data: img}
	}
	return out
}

func TestPortraitJPEG_KeepsJPEG(t *testing.T) {
	face := encodeTestJPEG(t, testFace(60, 80))
	if got := portraitJPEG(faces(face)); !bytes.Equal(got, face) {
		t.Error("a JPEG portrait wasn't carried unchanged")
	}
}

func TestPortraitJPEG_ConvertsJPEG2000(t *testing.T) {
	got := portraitJPEG(faces(encodeTestJP2(t, testFace(60, 80))))
	if got == nil {
		t.Fatal("a JPEG 2000 portrait wasn't converted")
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("converted portrait isn't a JPEG: %v", err)
	}
	if cfg.Width != 60 || cfg.Height != 80 {
		t.Errorf("converted portrait is %dx%d, want 60x80", cfg.Width, cfg.Height)
	}
}

func TestPortraitJPEG_UsesFirstFace(t *testing.T) {
	first := encodeTestJPEG(t, testFace(10, 10))
	second := encodeTestJPEG(t, testFace(20, 20))
	if got := portraitJPEG(faces(first, second)); !bytes.Equal(got, first) {
		t.Error("portrait isn't the first face image")
	}
}

func TestPortraitJPEG_NoUsableFace(t *testing.T) {
	jp2 := encodeTestJP2(t, testFace(16, 16))
	for name, f := range map[string][]document.ImageData{
		"none":             nil,
		"unknown format":   faces([]byte("GIF89a")),
		"corrupt JPEG":     faces([]byte{0xFF, 0xD8, 0xFF, 0x00}),
		"corrupt JPEG2000": faces(append(jp2[:len(jp2)/3:len(jp2)/3], 0, 0, 0)),
		"JPEG too large":   faces(encodeTestJPEG(t, testFace(maxPortraitSide+1, 1))),
		"JP2 too large":    faces(encodeTestJP2(t, testFace(1, maxPortraitSide+1))),
	} {
		if got := portraitJPEG(f); got != nil {
			t.Errorf("%s: got a %d-byte portrait, want none", name, len(got))
		}
	}
}
