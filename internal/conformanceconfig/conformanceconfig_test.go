package conformanceconfig_test

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
)

func TestBuildMdocNameSpaceElements(t *testing.T) {
	elements, err := conformanceconfig.BuildMdocNameSpaceElements("org.iso.18013.5.1", map[string]any{
		"given_name": "Jean",
		"birth_date": "1990-01-01",
		"portrait":   base64.StdEncoding.EncodeToString([]byte("jpeg-bytes")),
	})
	if err != nil {
		t.Fatalf("BuildMdocNameSpaceElements: %v", err)
	}
	ns, ok := elements["org.iso.18013.5.1"]
	if !ok {
		t.Fatalf("elements = %+v, want a org.iso.18013.5.1 namespace", elements)
	}

	if ns["given_name"] != "Jean" {
		t.Errorf("given_name = %v, want a plain string passthrough", ns["given_name"])
	}

	tag, ok := ns["birth_date"].(cbor.Tag)
	if !ok {
		t.Fatalf("birth_date = %T, want a cbor.Tag", ns["birth_date"])
	}
	if tag.Number != 1004 || tag.Content != "1990-01-01" {
		t.Errorf("birth_date tag = %+v, want {Number:1004 Content:1990-01-01}", tag)
	}

	portrait, ok := ns["portrait"].([]byte)
	if !ok || string(portrait) != "jpeg-bytes" {
		t.Errorf("portrait = %v (%T), want decoded []byte(\"jpeg-bytes\")", ns["portrait"], ns["portrait"])
	}
}

func TestBuildMdocNameSpaceElementsRejectsNonStringDate(t *testing.T) {
	if _, err := conformanceconfig.BuildMdocNameSpaceElements("ns", map[string]any{"birth_date": 19900101}); err == nil {
		t.Fatal("BuildMdocNameSpaceElements = nil error, want error for a non-string date claim")
	}
}

func TestBuildMdocNameSpaceElementsRejectsInvalidPortraitBase64(t *testing.T) {
	if _, err := conformanceconfig.BuildMdocNameSpaceElements("ns", map[string]any{"portrait": "not-base64!!"}); err == nil {
		t.Fatal("BuildMdocNameSpaceElements = nil error, want error for invalid base64 portrait")
	}
}

func TestBuildMdocNameSpaceElementsRejectsNonStringPortrait(t *testing.T) {
	if _, err := conformanceconfig.BuildMdocNameSpaceElements("ns", map[string]any{"portrait": 123}); err == nil {
		t.Fatal("BuildMdocNameSpaceElements = nil error, want error for a non-string portrait claim")
	}
}
