package androidkey

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// KeyPurpose is what a key may be used for (KeyMint's KeyPurpose).
type KeyPurpose int

// KeyPurpose values.
const (
	PurposeEncrypt   KeyPurpose = 0
	PurposeDecrypt   KeyPurpose = 1
	PurposeSign      KeyPurpose = 2
	PurposeVerify    KeyPurpose = 3
	PurposeWrapKey   KeyPurpose = 5
	PurposeAgreeKey  KeyPurpose = 6
	PurposeAttestKey KeyPurpose = 7
)

// Algorithm is a key's algorithm (KeyMint's Algorithm).
type Algorithm int

// Algorithm values.
const (
	AlgorithmRSA       Algorithm = 1
	AlgorithmEC        Algorithm = 3
	AlgorithmAES       Algorithm = 32
	AlgorithmTripleDES Algorithm = 33
	AlgorithmHMAC      Algorithm = 128
)

// ECCurve is an elliptic-curve key's curve (KeyMint's EcCurve).
type ECCurve int

// ECCurve values.
const (
	CurveP224    ECCurve = 0
	CurveP256    ECCurve = 1
	CurveP384    ECCurve = 2
	CurveP521    ECCurve = 3
	Curve25519   ECCurve = 4
	curveUnknown ECCurve = -1
)

// KeyOrigin is where a key came from (KeyMint's KeyOrigin).
type KeyOrigin int

// KeyOrigin values: only Generated is a key made inside the secure
// hardware that never left it.
const (
	OriginGenerated        KeyOrigin = 0
	OriginDerived          KeyOrigin = 1
	OriginImported         KeyOrigin = 2
	OriginReserved         KeyOrigin = 3
	OriginSecurelyImported KeyOrigin = 4
)

// AuthenticatorType is a bit set of the user authenticators a key's
// use may be authorised by (KeyMint's HardwareAuthenticatorType).
type AuthenticatorType uint32

// AuthenticatorType bits. AuthenticatorAny is every bit.
const (
	AuthenticatorPassword    AuthenticatorType = 1 << 0
	AuthenticatorFingerprint AuthenticatorType = 1 << 1
	AuthenticatorAny         AuthenticatorType = math.MaxUint32
)

// RootOfTrust is the device's verified boot state, as its bootloader
// told the secure hardware.
type RootOfTrust struct {
	// VerifiedBootKey is the key (or its digest) that verified the
	// system image.
	VerifiedBootKey []byte
	// DeviceLocked reports whether the bootloader is locked.
	DeviceLocked bool
	// VerifiedBootState is the boot verification's outcome.
	VerifiedBootState VerifiedBootState
	// VerifiedBootHash is the digest of the verified boot data, from
	// attestation version 3; nil before it.
	VerifiedBootHash []byte
}

// PackageInfo is one app package in an attestation application ID.
type PackageInfo struct {
	Name    string
	Version int64
}

// ApplicationID identifies the app that made a key: its packages (more
// than one only for apps sharing a user ID) and the SHA-256 digests of
// their signing certificates.
type ApplicationID struct {
	Packages         []PackageInfo
	SignatureDigests [][]byte
}

// AuthorizationList is the subset of KeyMint's AuthorizationList this
// package reads. A field's zero value (nil, false) means the tag is
// absent. Tags it doesn't read, including the device identifiers of ID
// attestation, are skipped; a tag that appears twice is malformed.
type AuthorizationList struct {
	Purposes  []KeyPurpose
	Algorithm *Algorithm
	KeySize   *int64
	Digests   []int64
	ECCurve   *ECCurve

	RollbackResistance bool

	// NoAuthRequired: the key may be used without user authentication.
	NoAuthRequired bool
	// UserAuthType are the authenticators that can authorise a use.
	UserAuthType *AuthenticatorType
	// AuthTimeout is how many seconds after an authentication the key
	// stays usable; absent, every use needs one.
	AuthTimeout                 *int64
	AllowWhileOnBody            bool
	TrustedUserPresenceRequired bool
	TrustedConfirmationRequired bool
	UnlockedDeviceRequired      bool

	CreationTime *time.Time
	Origin       *KeyOrigin
	RootOfTrust  *RootOfTrust
	// OSVersion is e.g. 140000 for Android 14.0.0.
	OSVersion *int64
	// OSPatchLevel is YYYYMM; VendorPatchLevel and BootPatchLevel are
	// YYYYMMDD.
	OSPatchLevel     *int64
	VendorPatchLevel *int64
	BootPatchLevel   *int64

	ApplicationID           *ApplicationID
	DeviceUniqueAttestation bool
	// ModuleHash is the digest of the device's APEX modules, from
	// attestation version 400.
	ModuleHash []byte
}

// HasPurpose reports whether p is among l's purposes.
func (l *AuthorizationList) HasPurpose(p KeyPurpose) bool { return slices.Contains(l.Purposes, p) }

// Authorization list tags (KeyMint's Tag numbers, without their type
// bits).
const (
	tagPurpose                     = 1
	tagAlgorithm                   = 2
	tagKeySize                     = 3
	tagDigest                      = 5
	tagECCurve                     = 10
	tagRollbackResistance          = 303
	tagNoAuthRequired              = 503
	tagUserAuthType                = 504
	tagAuthTimeout                 = 505
	tagAllowWhileOnBody            = 506
	tagTrustedUserPresenceRequired = 507
	tagTrustedConfirmationRequired = 508
	tagUnlockedDeviceRequired      = 509
	tagCreationDateTime            = 701
	tagOrigin                      = 702
	tagRootOfTrust                 = 704
	tagOSVersion                   = 705
	tagOSPatchLevel                = 706
	tagAttestationApplicationID    = 709
	tagVendorPatchLevel            = 718
	tagBootPatchLevel              = 719
	tagDeviceUniqueAttestation     = 720
	tagModuleHash                  = 724
)

// fieldParser reads one tag's inner value into l.
type fieldParser func(l *AuthorizationList, v asn1.RawValue) error

var fieldParsers = map[int]fieldParser{
	tagPurpose: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.Purposes, err = enumSet[KeyPurpose](v)
		return err
	},
	tagAlgorithm: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.Algorithm, err = enumValue[Algorithm](v)
		return err
	},
	tagKeySize: intInto(func(l *AuthorizationList) **int64 { return &l.KeySize }),
	tagDigest: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.Digests, err = integerSet(v)
		return err
	},
	tagECCurve: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.ECCurve, err = enumValue[ECCurve](v)
		return err
	},
	tagRollbackResistance: flag(func(l *AuthorizationList) *bool { return &l.RollbackResistance }),
	tagNoAuthRequired:     flag(func(l *AuthorizationList) *bool { return &l.NoAuthRequired }),
	tagUserAuthType: func(l *AuthorizationList, v asn1.RawValue) error {
		n, err := integer(v, asn1.TagInteger)
		if err != nil {
			return err
		}
		if n < 0 || n > math.MaxUint32 {
			return fmt.Errorf("authenticator type %d", n)
		}
		t := AuthenticatorType(n)
		l.UserAuthType = &t
		return nil
	},
	tagAuthTimeout:                 intInto(func(l *AuthorizationList) **int64 { return &l.AuthTimeout }),
	tagAllowWhileOnBody:            flag(func(l *AuthorizationList) *bool { return &l.AllowWhileOnBody }),
	tagTrustedUserPresenceRequired: flag(func(l *AuthorizationList) *bool { return &l.TrustedUserPresenceRequired }),
	tagTrustedConfirmationRequired: flag(func(l *AuthorizationList) *bool { return &l.TrustedConfirmationRequired }),
	tagUnlockedDeviceRequired:      flag(func(l *AuthorizationList) *bool { return &l.UnlockedDeviceRequired }),
	tagCreationDateTime: func(l *AuthorizationList, v asn1.RawValue) error {
		ms, err := integer(v, asn1.TagInteger)
		if err != nil {
			return err
		}
		t := time.UnixMilli(ms).UTC()
		l.CreationTime = &t
		return nil
	},
	tagOrigin: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.Origin, err = enumValue[KeyOrigin](v)
		return err
	},
	tagRootOfTrust: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.RootOfTrust, err = parseRootOfTrust(v)
		return err
	},
	tagOSVersion:    intInto(func(l *AuthorizationList) **int64 { return &l.OSVersion }),
	tagOSPatchLevel: intInto(func(l *AuthorizationList) **int64 { return &l.OSPatchLevel }),
	tagAttestationApplicationID: func(l *AuthorizationList, v asn1.RawValue) (err error) {
		l.ApplicationID, err = parseApplicationID(v)
		return err
	},
	tagVendorPatchLevel:        intInto(func(l *AuthorizationList) **int64 { return &l.VendorPatchLevel }),
	tagBootPatchLevel:          intInto(func(l *AuthorizationList) **int64 { return &l.BootPatchLevel }),
	tagDeviceUniqueAttestation: flag(func(l *AuthorizationList) *bool { return &l.DeviceUniqueAttestation }),
	tagModuleHash: func(l *AuthorizationList, v asn1.RawValue) error {
		b, err := octets(v)
		l.ModuleHash = slices.Clone(b)
		return err
	},
}

func flag(field func(*AuthorizationList) *bool) fieldParser {
	return func(l *AuthorizationList, v asn1.RawValue) error {
		*field(l) = true
		return null(v)
	}
}

func intInto(field func(*AuthorizationList) **int64) fieldParser {
	return func(l *AuthorizationList, v asn1.RawValue) error {
		n, err := integer(v, asn1.TagInteger)
		if err != nil {
			return err
		}
		*field(l) = &n
		return nil
	}
}

// enum is an int-valued KeyMint enumeration, encoded as an INTEGER.
type enum interface {
	~int
}

func enumOf[E enum](n int64) (E, error) {
	if n < 0 || n > math.MaxInt32 {
		return 0, fmt.Errorf("value %d out of range", n)
	}
	return E(n), nil
}

func enumValue[E enum](v asn1.RawValue) (*E, error) {
	n, err := integer(v, asn1.TagInteger)
	if err != nil {
		return nil, err
	}
	e, err := enumOf[E](n)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func enumSet[E enum](v asn1.RawValue) ([]E, error) {
	ns, err := integerSet(v)
	if err != nil {
		return nil, err
	}
	out := make([]E, len(ns))
	for i, n := range ns {
		if out[i], err = enumOf[E](n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseAuthorizationList reads an AuthorizationList: a SEQUENCE of
// EXPLICIT context-tagged fields.
func parseAuthorizationList(v asn1.RawValue) (AuthorizationList, error) {
	var l AuthorizationList
	fields, err := constructed(v, asn1.TagSequence, "AuthorizationList")
	if err != nil {
		return l, err
	}
	seen := make(map[int]bool, len(fields))
	for _, f := range fields {
		if f.Class != asn1.ClassContextSpecific || !f.IsCompound {
			return l, fmt.Errorf("a field with class %d tag %d isn't an EXPLICIT context tag", f.Class, f.Tag)
		}
		if seen[f.Tag] {
			return l, fmt.Errorf("tag %d appears twice", f.Tag)
		}
		seen[f.Tag] = true
		inner, err := single(f.Bytes)
		if err != nil {
			return l, fmt.Errorf("tag %d: %w", f.Tag, err)
		}
		parse, ok := fieldParsers[f.Tag]
		if !ok {
			continue // a field this package doesn't read, or a newer one
		}
		if err := parse(&l, inner); err != nil {
			return l, fmt.Errorf("tag %d: %w", f.Tag, err)
		}
	}
	return l, nil
}

// parseRootOfTrust reads
//
//	RootOfTrust ::= SEQUENCE {
//	    verifiedBootKey   OCTET_STRING,
//	    deviceLocked      BOOLEAN,
//	    verifiedBootState VerifiedBootState,
//	    verifiedBootHash  OCTET_STRING, -- from version 3
//	}
func parseRootOfTrust(v asn1.RawValue) (*RootOfTrust, error) {
	f, err := constructed(v, asn1.TagSequence, "RootOfTrust")
	if err != nil {
		return nil, err
	}
	if len(f) != 3 && len(f) != 4 {
		return nil, fmt.Errorf("RootOfTrust: %d fields", len(f))
	}
	var r RootOfTrust
	key, err := octets(f[0])
	if err != nil {
		return nil, fmt.Errorf("verifiedBootKey: %w", err)
	}
	r.VerifiedBootKey = slices.Clone(key)
	if r.DeviceLocked, err = boolean(f[1]); err != nil {
		return nil, fmt.Errorf("deviceLocked: %w", err)
	}
	state, err := integer(f[2], asn1.TagEnum)
	if err != nil {
		return nil, fmt.Errorf("verifiedBootState: %w", err)
	}
	if state < int64(Verified) || state > int64(Failed) {
		return nil, fmt.Errorf("verifiedBootState %d", state)
	}
	r.VerifiedBootState = VerifiedBootState(state)
	if len(f) == 4 {
		hash, err := octets(f[3])
		if err != nil {
			return nil, fmt.Errorf("verifiedBootHash: %w", err)
		}
		r.VerifiedBootHash = slices.Clone(hash)
	}
	return &r, nil
}

// parseApplicationID reads the OCTET STRING holding
//
//	AttestationApplicationId ::= SEQUENCE {
//	    package_infos     SET OF AttestationPackageInfo,
//	    signature_digests SET OF OCTET_STRING,
//	}
//	AttestationPackageInfo ::= SEQUENCE {
//	    package_name OCTET_STRING,
//	    version      INTEGER,
//	}
func parseApplicationID(v asn1.RawValue) (*ApplicationID, error) {
	der, err := octets(v)
	if err != nil {
		return nil, err
	}
	top, err := single(der)
	if err != nil {
		return nil, fmt.Errorf("AttestationApplicationId: %w", err)
	}
	f, err := constructed(top, asn1.TagSequence, "AttestationApplicationId")
	if err != nil {
		return nil, err
	}
	if len(f) != 2 {
		return nil, fmt.Errorf("AttestationApplicationId: %d fields", len(f))
	}
	infos, err := constructed(f[0], asn1.TagSet, "package_infos")
	if err != nil {
		return nil, err
	}
	digests, err := constructed(f[1], asn1.TagSet, "signature_digests")
	if err != nil {
		return nil, err
	}
	var id ApplicationID
	for _, info := range infos {
		p, err := parsePackageInfo(info)
		if err != nil {
			return nil, err
		}
		id.Packages = append(id.Packages, p)
	}
	for _, d := range digests {
		b, err := octets(d)
		if err != nil {
			return nil, fmt.Errorf("signature digest: %w", err)
		}
		id.SignatureDigests = append(id.SignatureDigests, slices.Clone(b))
	}
	return &id, nil
}

func parsePackageInfo(v asn1.RawValue) (PackageInfo, error) {
	f, err := constructed(v, asn1.TagSequence, "AttestationPackageInfo")
	if err != nil {
		return PackageInfo{}, err
	}
	if len(f) != 2 {
		return PackageInfo{}, errors.New("AttestationPackageInfo: want 2 fields")
	}
	name, err := octets(f[0])
	if err != nil {
		return PackageInfo{}, fmt.Errorf("package_name: %w", err)
	}
	version, err := integer(f[1], asn1.TagInteger)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("version: %w", err)
	}
	return PackageInfo{Name: string(name), Version: version}, nil
}
