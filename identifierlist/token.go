package identifierlist

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
)

// MediaType is the media type an identifier list is served and
// requested as (ISO/IEC 18013-5 §12.3.6.4: its content-type "shall be
// “application/identifierlist+cwt”"), and the COSE "typ" header (label
// 16, RFC 9596) IssueToken sets by default.
const MediaType = "application/identifierlist+cwt"

// BareTyp is MediaType without its "application/" prefix. It isn't
// conformant — §12.3.6.4 has the typ be MediaType — and exists only for
// compatibility with implementations that expect it, and Annex D.6's
// informative example omits the prefix too. IssueToken issues MediaType
// unless IssueOptions.Typ asks for this; verification accepts either.
//
// Annex D.6's example also misspells the typ, dropping the second "i"
// of "identifier"; neither IssueToken nor verification takes that
// spelling, which no clause of the standard names.
const BareTyp = "identifierlist+cwt"

// CWT claim keys: sub/exp/nbf/iat are RFC 8392's, ttl and status_list
// are Token Status List's (draft-ietf-oauth-status-list: ttl "TBD
// (requested assignment 65534)", status_list 65533), and
// identifier_list is ISO/IEC 18013-5 §12.3.6.4's 65530.
const (
	cwtClaimSub            = 2
	cwtClaimExp            = 4
	cwtClaimNbf            = 5
	cwtClaimIat            = 6
	cwtClaimTTL            = 65534
	cwtClaimStatusList     = 65533
	cwtClaimIdentifierList = 65530
)

// maxTokenBytes bounds a token this package issues, verifies or
// fetches. A list grows with the MSOs it revokes: 4 MiB holds well over
// two hundred thousand 16-byte identifiers.
const maxTokenBytes = 4 << 20

// maxIdentifiers bounds how many identifiers a list may hold, and sizes
// the decoder's limits. maxTokenBytes always binds first: an entry is a
// bstr key and an empty map, at least 3 bytes for the 256 one-byte
// identifiers, 4 for the 65,536 two-byte ones and 5 for any other, so a
// token within maxTokenBytes holds fewer than 860,000. This bound is
// the decoder's ceiling, kept above that so it never refuses a token
// within maxTokenBytes; IssueToken checks both all the same, so it
// never signs a list VerifyToken refuses.
const maxIdentifiers = 1 << 20

// Ref is an MSO's status.identifier_list element (ISO/IEC 18013-5
// §12.3.6.2, §12.3.6.4): the identifier the MSO is revoked by, the uri
// of the list, and optionally the certificate the list's x5chain must
// chain to. Its fields are credential/mdoc.IdentifierListRef's, so
// either converts to the other: identifierlist.Ref(*mso.Status.IdentifierList).
type Ref struct {
	ID          []byte
	URI         string
	Certificate []byte
}

// TokenClaims is an identifier list's CWT claims set.
type TokenClaims struct {
	// Sub is the uri the list is served at: the uri MSOs name.
	// REQUIRED.
	Sub string

	// Iat is when the list was signed, in seconds since 1970. REQUIRED.
	Iat int64

	// Exp is when the list stops being valid. REQUIRED (ISO/IEC
	// 18013-5 §12.3.6.3: "The exp claim shall be present"): IssueToken
	// and VerifyToken refuse a token without one.
	Exp *int64

	// TTL, if set, is how long a Relying Party may cache the list, in
	// seconds; it must be positive.
	TTL *int64

	// Identifiers are the revoked MSOs' identifiers, none of them
	// empty. A duplicate is issued once.
	Identifiers [][]byte
}

// Contains reports whether id is one of c's identifiers: whether an
// MSO with that identifier is revoked.
func (c TokenClaims) Contains(id []byte) bool {
	return slices.ContainsFunc(c.Identifiers, func(listed []byte) bool { return bytes.Equal(listed, id) })
}

// listed is Contains for claims as parsed, whose identifiers are
// sorted.
func (c TokenClaims) listed(id []byte) bool {
	_, ok := slices.BinarySearchFunc(c.Identifiers, id, bytes.Compare)
	return ok
}

// IssueOptions configures IssueToken.
type IssueOptions struct {
	// Typ is the COSE typ header; empty means MediaType. Set BareTyp
	// only for a Relying Party that refuses MediaType (see BareTyp).
	Typ string
}

// IssueToken signs claims into an identifier list: a COSE_Sign1_Tagged
// CWT with alg, the typ header and chain in the protected x5chain
// header (ISO/IEC 18013-5 §12.3.6.3, RFC 9360), leaf first and without
// the trust anchor. It refuses what VerifyToken would: claims without
// exp, an empty identifier, or a list with more identifiers or bytes
// than this package reads.
//
// It caches nothing and does no I/O, so an issuer can pre-sign the list
// and serve the bytes from anywhere — but the host must serve them as
// "Content-Type: application/identifierlist+cwt" exactly (MediaType),
// or Checker refuses the list.
func IssueToken(signer crypto.Signer, alg oid4vci.COSEAlg, claims TokenClaims, chain []*x509.Certificate, opts IssueOptions) ([]byte, error) {
	if err := claims.validate(); err != nil {
		return nil, err
	}
	ders, err := certchain.SignerChainDERs(signer, chain)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: %w", err)
	}
	typ := opts.Typ
	if typ == "" {
		typ = MediaType
	}
	if typ != MediaType && typ != BareTyp {
		return nil, fmt.Errorf("identifierlist: IssueOptions.Typ is %q, want %q or %q", typ, MediaType, BareTyp)
	}

	identifiers := make(map[cbor.ByteString]map[string]any, len(claims.Identifiers))
	for _, id := range claims.Identifiers {
		identifiers[cbor.ByteString(id)] = map[string]any{}
	}
	if len(identifiers) > maxIdentifiers {
		return nil, fmt.Errorf("identifierlist: %d identifiers, over the %d allowed", len(identifiers), maxIdentifiers)
	}
	payload := map[int]any{
		cwtClaimSub:            claims.Sub,
		cwtClaimIat:            claims.Iat,
		cwtClaimExp:            *claims.Exp,
		cwtClaimIdentifierList: map[string]any{"identifiers": identifiers},
	}
	if claims.TTL != nil {
		payload[cwtClaimTTL] = *claims.TTL
	}
	raw, err := encMode.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: marshal CWT claims: %w", err)
	}
	token, err := cose.SignTagged(alg, signer, cose.Headers{Typ: typ, X5Chain: ders}, cose.Headers{}, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: sign CWT: %w", err)
	}
	if len(token) > maxTokenBytes {
		return nil, fmt.Errorf("identifierlist: the token is %d bytes, over the %d allowed", len(token), maxTokenBytes)
	}
	return token, nil
}

func (c TokenClaims) validate() error {
	switch {
	case c.Sub == "":
		return errors.New("identifierlist: TokenClaims.Sub is required")
	case c.Iat <= 0:
		return errors.New("identifierlist: TokenClaims.Iat is required")
	case c.Exp == nil:
		return errors.New("identifierlist: TokenClaims.Exp is required (ISO/IEC 18013-5 §12.3.6.3)")
	case *c.Exp <= c.Iat:
		return errors.New("identifierlist: TokenClaims.Exp must be after Iat")
	case c.TTL != nil && *c.TTL <= 0:
		return errors.New("identifierlist: TokenClaims.TTL must be positive")
	case slices.ContainsFunc(c.Identifiers, func(id []byte) bool { return len(id) == 0 }):
		return errors.New("identifierlist: TokenClaims.Identifiers holds an empty identifier")
	}
	return nil
}

// VerifyOptions configures VerifyToken, Check and Checker. Its fields
// mean what statuslist.VerifyOptions's of the same name do.
type VerifyOptions struct {
	// Now is the time the token's times and its signer's certificates
	// are checked at; it defaults to time.Now.
	Now func() time.Time

	// MaxAge, if set, refuses a token issued longer ago: a list signed
	// before a revocation stays valid until its exp, so anyone serving
	// bytes at the uri could replay it until then. It is the only bound
	// on that replay this package sets: zero leaves freshness to exp,
	// however far ahead the issuer put it, and a token's ttl only says
	// how long it may be cached. Negative is an error, not "no limit".
	MaxAge time.Duration

	// MaxClockSkew is how far in the future iat and nbf may be; zero
	// means a minute.
	MaxClockSkew time.Duration

	// LeafPolicy, if set, is run on the signer's chain-verified
	// certificate and its verified paths, and can refuse it: to require
	// the signer's role, an extended key usage say. Check and Checker
	// bind the signer to the mdoc's issuer (ISO/IEC 18013-5 §12.3.6.2)
	// themselves; LeafPolicy narrows that further, never widens it.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// UnboundSigner decides the list's signer when Check and Checker
	// have nothing to bind it to the mdoc's issuer with: the reference
	// names no Certificate and no document signer path is given. It is
	// run, as LeafPolicy is and before it, on a signer that chains to
	// the roots: nil to accept it, an error to refuse. Nil refuses every
	// such check, since any CA under the roots could otherwise sign a
	// list that says another issuer's MSO isn't revoked. AnyListSigner
	// accepts every signer under the roots: set it only where every CA
	// they anchor may decide every MSO's revocation — roots of one
	// issuer alone, say. VerifyToken, which binds no signer, ignores it.
	UnboundSigner func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// Revocation, if set, checks the signer's certificate chain for
	// revocation; see certrevocation.
	Revocation certrevocation.Checker
}

// AnyListSigner is a VerifyOptions.UnboundSigner accepting every
// identifier list signer under the roots.
func AnyListSigner(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// errUnboundSigner refuses a check that nothing ties the list's signer
// to the mdoc's issuer for.
var errUnboundSigner = errors.New("identifierlist: the list's signer can't be bound to the mdoc's issuer: pass the MSO's document signer path (its IssuerAuth x5chain as verified), or set VerifyOptions.UnboundSigner (AnyListSigner accepts every signer under the roots)")

func (o VerifyOptions) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

// VerifyToken verifies an identifier list carrying its signer's
// x5chain in its protected header (ISO/IEC 18013-5 §12.3.6.3), tagged
// or untagged: the chain to roots (on a path LeafPolicy approves and
// Revocation passes), the signature with its leaf's key, the typ header
// (MediaType or BareTyp, case-insensitively), its claims —
// identifier_list present, Token Status List's status_list absent
// (§12.3.6.4) — and its times, refusing a token without exp
// (§12.3.6.3). It doesn't bind the signer to an mdoc's issuer or check
// sub against a reference: that's Check's job.
func VerifyToken(ctx context.Context, token []byte, roots *x509.CertPool, opts VerifyOptions) (TokenClaims, error) {
	parsed, _, err := verifyToken(ctx, token, roots, opts.LeafPolicy, opts)
	return parsed.claims, err
}

// parsedClaims are a list's claims as read from its payload: they
// depend on the token's bytes alone, so a Cache can keep them
// (tokenMemo).
type parsedClaims struct {
	claims TokenClaims
	nbf    *int64
}

// verifyToken is VerifyToken with policy in place of opts.LeafPolicy,
// with the claims as parsed and the signer's chain the token carries.
func verifyToken(ctx context.Context, token []byte, roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, opts VerifyOptions) (parsedClaims, [][]byte, error) {
	trust := signerTrustAt(roots, policy, opts)
	chain, _, err := trust.Chain(token)
	if err != nil {
		return parsedClaims{}, nil, fmt.Errorf("identifierlist: %w", err)
	}
	leaf, alg, err := trust.Signer(ctx, chain)
	if err != nil {
		return parsedClaims{}, nil, fmt.Errorf("identifierlist: %w", err)
	}
	protected, _, raw, err := cose.VerifyMax(alg, leaf.PublicKey, token, nil, maxTokenBytes)
	if err != nil {
		return parsedClaims{}, nil, fmt.Errorf("identifierlist: verify CWT signature: %w", err)
	}
	if !strings.EqualFold(protected.Typ, MediaType) && !strings.EqualFold(protected.Typ, BareTyp) {
		return parsedClaims{}, nil, fmt.Errorf("identifierlist: CWT typ is %q, want %q or %q", protected.Typ, MediaType, BareTyp)
	}
	var parsed parsedClaims
	if parsed.claims, parsed.nbf, err = parseClaims(raw); err != nil {
		return parsedClaims{}, nil, err
	}
	if err := parsed.checkTimes(opts, trust.Now); err != nil {
		return parsedClaims{}, nil, err
	}
	return parsed, chain, nil
}

// signerTrustAt is how a list's signer is verified under roots and
// policy, at opts's Now, read once. §12.3.6.3 has the x5chain
// protected, where the signature covers it.
func signerTrustAt(roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, opts VerifyOptions) cose.X5ChainTrust {
	return cose.X5ChainTrust{
		MaxBytes: maxTokenBytes, ProtectedOnly: true, Roots: roots, Policy: policy, Revocation: opts.Revocation, Now: opts.now(),
	}
}

// checkTimes checks p's times against opts at now; a list must have
// exp (§12.3.6.3).
func (p parsedClaims) checkTimes(opts VerifyOptions, now time.Time) error {
	window := jwtdate.Window{MaxAge: opts.MaxAge, MaxClockSkew: opts.MaxClockSkew, RequireExp: true}
	if err := window.Check(p.claims.Iat, p.claims.Exp, p.nbf, now); err != nil {
		return fmt.Errorf("identifierlist: %w", err)
	}
	return nil
}

// Check verifies token as VerifyToken does, binds its signer to the
// mdoc's issuer as ISO/IEC 18013-5 §12.3.6.2 requires, checks its sub
// is ref.URI, and reports whether ref.ID is on it: whether the MSO is
// revoked. With an error, revoked is true, so a caller that reads it
// alone refuses the MSO.
//
// When ref names a Certificate, the token's x5chain must chain to it
// alone: roots aren't consulted. Otherwise the chain must verify to
// roots on a path through the certificate that signed the document
// signer (for an mDL, the IACA), with documentSignerPath the MSO's
// IssuerAuth x5chain as verified, leaf first, with or without its
// anchor (credential/mdoc.IdentifierListTrust). With neither, the
// check is refused unless opts.UnboundSigner accepts the signer, which
// must then chain to roots.
//
// ref and documentSignerPath must come from an MSO whose signature and
// document signer chain were verified: an unverified MSO could name
// any Certificate, and with it any list.
func Check(ctx context.Context, token []byte, roots *x509.CertPool, ref Ref, documentSignerPath []*x509.Certificate, opts VerifyOptions) (revoked bool, claims TokenClaims, err error) {
	parsed, _, err := check(ctx, token, roots, ref, documentSignerPath, opts)
	if err != nil {
		return true, TokenClaims{}, err
	}
	return parsed.claims.listed(ref.ID), parsed.claims, nil
}

func (r Ref) validate() error {
	if len(r.ID) == 0 || r.URI == "" {
		return errors.New("identifierlist: the reference needs an id and a uri")
	}
	return nil
}

// check is Check, before deciding revoked, also returning the signer's
// chain the token carries.
func check(ctx context.Context, token []byte, roots *x509.CertPool, ref Ref, documentSignerPath []*x509.Certificate, opts VerifyOptions) (parsedClaims, [][]byte, error) {
	roots, policy, err := boundSigner(roots, ref, documentSignerPath, opts)
	if err != nil {
		return parsedClaims{}, nil, err
	}
	parsed, chain, err := verifyToken(ctx, token, roots, policy, opts)
	if err != nil {
		return parsedClaims{}, nil, err
	}
	if err := parsed.checkSub(ref); err != nil {
		return parsedClaims{}, nil, err
	}
	return parsed, chain, nil
}

// recheck is check of a token whose chain and parsed claims a check
// found before, from them alone: the chain is verified again to the
// roots ref and documentSignerPath bind, at opts's Now, on a path the
// policy approves and opts.Revocation passes, and the claims checked
// again against opts and ref. What depends on the bytes alone — the
// signature under the chain's leaf, the typ and the parse — isn't done
// again.
func recheck(ctx context.Context, chain [][]byte, parsed parsedClaims, roots *x509.CertPool, ref Ref, documentSignerPath []*x509.Certificate, opts VerifyOptions) error {
	roots, policy, err := boundSigner(roots, ref, documentSignerPath, opts)
	if err != nil {
		return err
	}
	trust := signerTrustAt(roots, policy, opts)
	if _, _, err := trust.Signer(ctx, chain); err != nil {
		return fmt.Errorf("identifierlist: %w", err)
	}
	if err := parsed.checkTimes(opts, trust.Now); err != nil {
		return err
	}
	return parsed.checkSub(ref)
}

// boundSigner is the roots and leaf policy a list's signer must meet
// for ref, refusing a ref that's incomplete or binds no roots.
func boundSigner(roots *x509.CertPool, ref Ref, documentSignerPath []*x509.Certificate, opts VerifyOptions) (*x509.CertPool, func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	if err := ref.validate(); err != nil {
		return nil, nil, err
	}
	roots, policy, err := signerTrust(roots, ref, documentSignerPath, opts)
	if err != nil {
		return nil, nil, err
	}
	if roots == nil {
		return nil, nil, errors.New("identifierlist: no trust anchors: roots is nil and the reference names no certificate")
	}
	return roots, policy, nil
}

// checkSub checks p is ref's list.
func (p parsedClaims) checkSub(ref Ref) error {
	if p.claims.Sub != ref.URI {
		return fmt.Errorf("identifierlist: token sub %q isn't the reference's uri %q", p.claims.Sub, ref.URI)
	}
	return nil
}

// signerTrust is the roots and leaf policy a list's signer must meet
// for ref, as Check describes.
func signerTrust(roots *x509.CertPool, ref Ref, documentSignerPath []*x509.Certificate, opts VerifyOptions) (*x509.CertPool, func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	if len(ref.Certificate) == 0 && len(documentSignerPath) == 0 {
		if opts.UnboundSigner == nil {
			return nil, nil, errUnboundSigner
		}
		return roots, certchain.BothPolicies(opts.UnboundSigner, opts.LeafPolicy), nil
	}
	trust, err := mdoc.IdentifierListTrust(&mdoc.IdentifierListRef{Certificate: ref.Certificate}, documentSignerPath)
	if err != nil {
		return nil, nil, fmt.Errorf("identifierlist: the list's signer can't be bound to the mdoc's issuer: %w", err)
	}
	if trust.Roots != nil {
		return trust.Roots, opts.LeafPolicy, nil
	}
	return roots, certchain.BothPolicies(trust.LeafPolicy, opts.LeafPolicy), nil
}

type identifierListClaim struct {
	Identifiers cbor.RawMessage `cbor:"identifiers"`
}

func parseClaims(raw []byte) (TokenClaims, *int64, error) {
	var decoded map[int]cbor.RawMessage
	if err := decMode.Unmarshal(raw, &decoded); err != nil {
		return TokenClaims{}, nil, fmt.Errorf("identifierlist: unmarshal CWT claims: %w", err)
	}
	var claims TokenClaims
	if err := decMode.Unmarshal(decoded[cwtClaimSub], &claims.Sub); err != nil || claims.Sub == "" {
		return TokenClaims{}, nil, errors.New("identifierlist: CWT is missing the required sub claim")
	}
	iat, err := numericDate(decoded, cwtClaimIat, "iat")
	if err != nil {
		return TokenClaims{}, nil, err
	}
	// An iat of 0 is refused as missing, as statuslist refuses it.
	if iat == nil || *iat == 0 {
		return TokenClaims{}, nil, errors.New("identifierlist: CWT is missing the required iat claim")
	}
	claims.Iat = *iat
	if claims.Exp, err = numericDate(decoded, cwtClaimExp, "exp"); err != nil {
		return TokenClaims{}, nil, err
	}
	nbf, err := numericDate(decoded, cwtClaimNbf, "nbf")
	if err != nil {
		return TokenClaims{}, nil, err
	}
	if v, ok := decoded[cwtClaimTTL]; ok {
		var ttl int64
		if err := decMode.Unmarshal(v, &ttl); err != nil || ttl <= 0 {
			return TokenClaims{}, nil, errors.New("identifierlist: ttl claim isn't a positive integer")
		}
		claims.TTL = &ttl
	}
	// §12.3.6.4: "The StatusList claim shall not be present in the CWT
	// claims set".
	if _, ok := decoded[cwtClaimStatusList]; ok {
		return TokenClaims{}, nil, errors.New("identifierlist: CWT carries a status_list claim (ISO/IEC 18013-5 §12.3.6.4)")
	}

	v, ok := decoded[cwtClaimIdentifierList]
	if !ok {
		return TokenClaims{}, nil, errors.New("identifierlist: CWT is missing the required identifier_list claim")
	}
	// The walk above checked the whole claims set, duplicate keys at
	// every depth included, so the list is decoded without walking it
	// again, and its identifiers are read in place rather than built
	// into a map: a list near maxTokenBytes holds most of a million.
	var list identifierListClaim
	if err := decMode.DecMode.Unmarshal(v, &list); err != nil {
		return TokenClaims{}, nil, fmt.Errorf("identifierlist: identifier_list claim: %w", err)
	}
	if !strictcbor.IsMap(list.Identifiers) {
		return TokenClaims{}, nil, errors.New("identifierlist: identifier_list claim has no identifiers map")
	}
	if claims.Identifiers, err = identifiers(list.Identifiers); err != nil {
		return TokenClaims{}, nil, err
	}
	return claims, nbf, nil
}

// identifiers reads the identifiers map of an identifier_list claim
// (ISO/IEC 18013-5 §12.3.6.4: a non-empty Identifier, a bstr, to its
// IdentifierInfo, a map), sorted. They share raw's memory.
func identifiers(raw []byte) ([][]byte, error) {
	n := 0
	if err := strictcbor.Entries(raw, func(_, _ []byte) error { n++; return nil }); err != nil {
		return nil, fmt.Errorf("identifierlist: identifiers: %w", err)
	}
	ids := make([][]byte, 0, n)
	err := strictcbor.Entries(raw, func(key, info []byte) error {
		id, ok := strictcbor.Bytes(key)
		switch {
		case !ok:
			return errors.New("identifierlist: an identifier isn't a byte string")
		case len(id) == 0:
			return errors.New("identifierlist: the list holds an empty identifier")
		case !strictcbor.IsMap(info):
			return fmt.Errorf("identifierlist: identifier %x's IdentifierInfo isn't a map", id)
		}
		ids = append(ids, id)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ids, bytes.Compare)
	return ids, nil
}

// numericDate reads claim key as a CWT NumericDate (RFC 8392 §2: an
// integer or floating-point number of seconds), fraction dropped; nil
// when it's absent.
func numericDate(decoded map[int]cbor.RawMessage, key int, name string) (*int64, error) {
	v, ok := decoded[key]
	if !ok {
		return nil, nil
	}
	var n any
	if err := decMode.Unmarshal(v, &n); err != nil {
		return nil, fmt.Errorf("identifierlist: %s claim: %w", name, err)
	}
	at, err := jwtdate.FromCBOR(n)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: %s claim: %w", name, err)
	}
	unix := at.Unix()
	return &unix, nil
}

// encMode encodes claims deterministically (RFC 8949 §4.2.1), so the
// same list signs over the same bytes.
var encMode = func() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("identifierlist: build CBOR encoder: " + err.Error())
	}
	return mode
}()

// decMode decodes a token's claims: no duplicate map keys at any depth
// (two entries for one claim would let decoders disagree), exact field
// matching, and bounds sized for a list of maxIdentifiers.
var decMode = func() strictcbor.DecMode {
	mode, err := cbor.DecOptions{
		MaxNestedLevels:   16,
		MaxMapPairs:       maxIdentifiers,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic("identifierlist: build CBOR decoder: " + err.Error())
	}
	return strictcbor.Wrap(mode).WithMaxItems(4 * maxIdentifiers)
}()
