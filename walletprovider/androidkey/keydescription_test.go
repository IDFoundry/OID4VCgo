package androidkey_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// TestParseKeyDescription_Versions: every attestation version parses,
// with the fields it added, and a future version's unknown tags are
// skipped.
func TestParseKeyDescription_Versions(t *testing.T) {
	versions := append(slices.Clone(androidkey.KnownAttestationVersions), 600)
	for _, version := range versions {
		s := goodSpec(t)
		s.version = version
		s.hw = append(s.hw,
			field{303, derNull()}, field{504, derInt(t, 0xffffffff)}, field{505, derInt(t, 300)},
			field{507, derNull()}, field{508, derNull()}, field{509, derNull()}, field{720, derNull()},
			field{724, derOctets(t, []byte("module hash"))},
			// mlDsaVariant, from version 500.
			field{11, derInt(t, 1)},
			// Tags this package doesn't read: padding, a device ID, and
			// ones no version defines yet.
			field{6, derIntSet(t, 1)}, field{710, derOctets(t, []byte("brand"))}, field{725, derNull()}, field{9999, derInt(t, 7)})
		kd, err := androidkey.ParseKeyDescription(s.encode(t))
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		hw := kd.HardwareEnforced
		if kd.AttestationVersion != version || kd.KeyMintVersion != version || !bytes.Equal(kd.AttestationChallenge, testChallenge) ||
			*hw.Algorithm != androidkey.AlgorithmEC || *hw.KeySize != 256 || *hw.ECCurve != androidkey.CurveP256 ||
			*hw.Origin != androidkey.OriginGenerated || !hw.NoAuthRequired || !hw.RollbackResistance ||
			*hw.UserAuthType != androidkey.AuthenticatorAny || *hw.AuthTimeout != 300 || !hw.TrustedUserPresenceRequired ||
			!hw.TrustedConfirmationRequired || !hw.UnlockedDeviceRequired || !hw.DeviceUniqueAttestation ||
			string(hw.ModuleHash) != "module hash" || *hw.OSVersion != 150000 || *hw.OSPatchLevel != 202509 ||
			*hw.VendorPatchLevel != 20250901 || *hw.BootPatchLevel != 20250901 || !slices.Equal(hw.Digests, []int64{4}) {
			t.Errorf("version %d: hardware list %+v", version, hw)
		}
		rot := hw.RootOfTrust
		if !rot.DeviceLocked || rot.VerifiedBootState != androidkey.Verified || !bytes.Equal(rot.VerifiedBootKey, bootKey[:]) || len(rot.VerifiedBootHash) != 32 {
			t.Errorf("version %d: root of trust %+v", version, rot)
		}
		sw := kd.SoftwareEnforced
		if !sw.CreationTime.Equal(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)) || sw.ApplicationID.Packages[0] != (androidkey.PackageInfo{Name: appPackage, Version: 42}) {
			t.Errorf("version %d: software list %+v", version, sw)
		}
	}
}

// TestParseKeyDescription_Lenient: encodings real Keymaster
// implementations produce that strict DER refuses, but whose meaning is
// plain, parse: a BOOLEAN true of 0x01, an INTEGER with a redundant
// leading byte, and a root of trust without the boot hash (version 1
// and 2).
func TestParseKeyDescription_Lenient(t *testing.T) {
	s := goodSpec(t)
	rot := derSeq(t, derOctets(t, bootKey[:]), []byte{0x01, 0x01, 0x01}, derEnum(t, 0))
	s.hw = replace(s.hw, 704, rot)
	s.hw = replace(s.hw, 706, []byte{0x02, 0x04, 0x00, 0x03, 0x16, 0x8d}) // 202381, padded
	kd, err := androidkey.ParseKeyDescription(s.encode(t))
	if err != nil {
		t.Fatal(err)
	}
	if r := kd.HardwareEnforced.RootOfTrust; !r.DeviceLocked || r.VerifiedBootHash != nil || *kd.HardwareEnforced.OSPatchLevel != 202381 {
		t.Errorf("parsed %+v, patch level %d", r, *kd.HardwareEnforced.OSPatchLevel)
	}
}

// TestParseKeyDescription_Refuses: malformed key descriptions are
// refused with ErrMalformed.
func TestParseKeyDescription_Refuses(t *testing.T) {
	good := goodSpec(t).encode(t)
	with := func(f func(s *spec)) []byte {
		s := goodSpec(t)
		f(&s)
		return s.encode(t)
	}
	hwWith := func(tag int, inner []byte) []byte {
		return with(func(s *spec) { s.hw = replace(s.hw, tag, inner) })
	}
	hwPlus := func(raw []byte) []byte {
		s := goodSpec(t)
		var elems [][]byte
		for _, f := range s.hw {
			elems = append(elems, explicit(t, f))
		}
		return derSeq(t, derInt(t, 300), derEnum(t, 1), derInt(t, 300), derEnum(t, 1),
			derOctets(t, testChallenge), derOctets(t, nil), authList(t, s.sw), derSeq(t, append(elems, raw)...))
	}
	sevenFields := derSeq(t, derInt(t, 300), derEnum(t, 1), derInt(t, 300), derEnum(t, 1), derOctets(t, nil), derOctets(t, nil), derSeq(t))
	for name, der := range map[string][]byte{
		"empty":                   nil,
		"not a SEQUENCE":          {0x04, 0x00},
		"trailing data":           append(slices.Clone(good), 0),
		"truncated":               good[:len(good)-1],
		"seven fields":            sevenFields,
		"version 0":               with(func(s *spec) { s.version = 0 }),
		"version too large":       with(func(s *spec) { s.version = 1 << 21 }),
		"unknown security level":  with(func(s *spec) { s.keyLevel = 3 }),
		"negative security level": with(func(s *spec) { s.attLevel = -1 }),
		"129-byte challenge":      with(func(s *spec) { s.challenge = make([]byte, 129) }),
		"oversized":               derSeq(t, derOctets(t, make([]byte, androidkey.MaxExtensionBytes))),
		"duplicate tag":           hwPlus(explicit(t, field{702, derInt(t, 0)})),
		"implicit tag":            hwPlus([]byte{0x81, 0x01, 0x00}),
		"universal element":       hwPlus(derInt(t, 1)),
		"two values in a field":   hwPlus(explicit(t, field{800, append(derInt(t, 1), derInt(t, 2)...)})),
		"purpose not a SET":       hwWith(1, derSeq(t, derInt(t, 2))),
		"purpose out of range":    hwWith(1, derIntSet(t, -1)),
		"algorithm not INTEGER":   hwWith(2, derOctets(t, []byte{3})),
		"oversized INTEGER":       hwWith(705, []byte{0x02, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}),
		"INTEGER past int64":      hwWith(705, []byte{0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}),
		"empty INTEGER":           hwWith(705, []byte{0x02, 0x00}),
		"NULL with content":       hwWith(503, []byte{0x05, 0x01, 0x00}),
		"flag not NULL":           hwWith(503, derBool(true)),
		"auth type negative":      hwWith(504, derInt(t, -1)),
		"auth type too large":     hwWith(504, derInt(t, 1<<32)),
		"creation time not INTEGER": with(func(s *spec) {
			s.sw = replace(s.sw, 701, derOctets(t, nil))
		}),
		"root of trust short":      hwWith(704, derSeq(t, derOctets(t, nil), derBool(true))),
		"root of trust boot state": hwWith(704, rootOfTrust(t, nil, true, 4)),
		"root of trust key":        hwWith(704, derSeq(t, derBool(true), derBool(true), derEnum(t, 0))),
		"root of trust boolean":    hwWith(704, derSeq(t, derOctets(t, nil), []byte{0x01, 0x02, 0xff, 0xff}, derEnum(t, 0))),
		"root of trust hash":       hwWith(704, derSeq(t, derOctets(t, nil), derBool(true), derEnum(t, 0), derBool(true))),
		"root of trust state type": hwWith(704, derSeq(t, derOctets(t, nil), derBool(true), derInt(t, 0))),
		"app ID not OCTET STRING": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derSeq(t))
		}),
		"app ID not DER": with(func(s *spec) { s.sw = replace(s.sw, 709, derOctets(t, []byte{0x30, 0x05})) }),
		"app ID one field": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t))))
		}),
		"app ID package not SEQUENCE": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t, derInt(t, 1)), derSet(t))))
		}),
		"app ID package fields": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t, derSeq(t, derOctets(t, []byte("a")))), derSet(t))))
		}),
		"app ID package name": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t, derSeq(t, derInt(t, 1), derInt(t, 1))), derSet(t))))
		}),
		"app ID package version": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t, derSeq(t, derOctets(t, nil), derOctets(t, nil))), derSet(t))))
		}),
		"app ID digest": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t), derSet(t, derInt(t, 1)))))
		}),
		"app ID digests not SET": with(func(s *spec) {
			s.sw = replace(s.sw, 709, derOctets(t, derSeq(t, derSet(t), derSeq(t))))
		}),
		"module hash": hwWith(724, derInt(t, 1)),
		"too many elements": with(func(s *spec) {
			for i := range 130 {
				s.sw = append(s.sw, field{1000 + i, derNull()})
			}
		}),
		"challenge not OCTET STRING": derSeq(t, derInt(t, 300), derEnum(t, 1), derInt(t, 300), derEnum(t, 1),
			derInt(t, 1), derOctets(t, nil), derSeq(t), derSeq(t)),
		"unique ID not OCTET STRING": derSeq(t, derInt(t, 300), derEnum(t, 1), derInt(t, 300), derEnum(t, 1),
			derOctets(t, nil), derInt(t, 1), derSeq(t), derSeq(t)),
		"software list not SEQUENCE": derSeq(t, derInt(t, 300), derEnum(t, 1), derInt(t, 300), derEnum(t, 1),
			derOctets(t, nil), derOctets(t, nil), derSet(t), derSeq(t)),
		"version not INTEGER": derSeq(t, derOctets(t, nil), derEnum(t, 1), derInt(t, 300), derEnum(t, 1),
			derOctets(t, nil), derOctets(t, nil), derSeq(t), derSeq(t)),
		"level not ENUMERATED": derSeq(t, derInt(t, 300), derInt(t, 1), derInt(t, 300), derEnum(t, 1),
			derOctets(t, nil), derOctets(t, nil), derSeq(t), derSeq(t)),
	} {
		kd, err := androidkey.ParseKeyDescription(der)
		if err == nil {
			t.Errorf("%s: parsed, %+v", name, kd)
		} else if !errors.Is(err, androidkey.ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}

func TestEnumStrings(t *testing.T) {
	for got, want := range map[string]string{
		androidkey.StrongBox.String():             "StrongBox",
		androidkey.SecurityLevel(7).String():      "SecurityLevel(7)",
		androidkey.SelfSigned.String():            "SelfSigned",
		androidkey.VerifiedBootState(-1).String(): "VerifiedBootState(-1)",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	if !strings.Contains(androidkey.Software.String(), "Software") || androidkey.Software.Hardware() {
		t.Error("Software")
	}
}
