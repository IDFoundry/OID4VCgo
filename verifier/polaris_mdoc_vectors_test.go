package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// Polaris negative vectors for mso_mdoc presentations under OpenID4VP 1.0:
// github.com/EgorKhaklin/polaris-id, lab/interop/negative-vectors.
// mdoc-vectors.json holds valid presentations, each a DeviceResponse and the
// verifier's request (the controls, which every verifier must accept), and
// presentations that each differ from a control in one thing, in the
// response or in the request, which the file says a verifier refuses, with
// the clauses it cites (for class policy, the policy it names): in the
// SessionTranscript, the device authentication, the request, the IssuerAuth
// and the MSO. Each refusal carries a repaired twin: the same vector with
// its one defect put back, which must be accepted. This test feeds each
// vector and each twin to VerifyResponse and compares the verdict with the
// file's.
//
// The file isn't vendored. The Polaris vectors workflow checks polaris-id
// out at a pinned commit and sets POLARIS_MDOC_VECTORS to the file; without
// it this test is skipped, so a plain `go test ./...` needs no network. The
// file's SHA-256 is pinned too, so the checkout can't change under the test.
//
// To move the pin: read what changed in the vectors since the commit below,
// then set both constants and the ref of the mdoc-vectors job in
// .github/workflows/polaris-vectors.yml to the new commit. The hash is
// sha256sum lab/interop/negative-vectors/mdoc-vectors.json in that checkout.
const (
	polarisMdocVectorsCommit = "781c879fa83d92132f7cc25f7468cad890bbb13b"
	polarisMdocVectorsSHA256 = "2525e629f92adad0a4a44649f7868eb9ecab84bc60135a126862f118a28857de"
)

// polarisMdocKnownGaps are the refusals this package does not make at the
// pinned commit, by vector id, with the layer and the clause each rests on.
// A listed vector that is accepted is logged as a known gap and does not
// fail the test. A listed vector that is now refused fails the test: remove
// it from this map. Any other vector with a wrong verdict fails the test,
// except one under a policy in polarisMdocPoliciesNotApplied (see there),
// and so does a refused control or a refused twin. Controls are never
// listed.
var polarisMdocKnownGaps = map[string]polarisGap{}

// polarisMdocPoliciesNotApplied are the file's policies this package
// doesn't apply, by name, with why, from the package's own code. A vector
// under one of them is expected to be accepted: accepted, it is logged as a
// policy not applied; refused, it fails the test: remove the policy from
// this map. A policy that isn't listed is expected to reach the file's
// verdict.
var polarisMdocPoliciesNotApplied = map[string]string{}

// polarisMdocLayerReasons are the Reasons a refusal at each of the file's
// layers is expected to carry. A refusal with another Reason was made for
// something other than the vector's one defect, and fails the test. The
// device authentication covers the DeviceKey in the MSO (an
// invalid_credential) and a missing DeviceSignature (malformed) as well as
// the signature itself; the IssuerAuth covers COSE headers the package
// can't parse (malformed).
var polarisMdocLayerReasons = map[string][]Reason{
	"session-transcript": {ReasonHolderBinding},
	"device-auth":        {ReasonHolderBinding, ReasonInvalidCredential, ReasonMalformed},
	"request":            {ReasonNotAnswered},
	"issuer-auth":        {ReasonInvalidCredential, ReasonMalformed},
	"mso":                {ReasonInvalidCredential},
}

type polarisMdocFile struct {
	Version  string              `json:"version"`
	Policies map[string]string   `json:"policies"`
	Vectors  []polarisMdocVector `json:"vectors"`
}

type polarisMdocVector struct {
	ID              string            `json:"id"`
	Layer           string            `json:"layer"`
	Class           string            `json:"class"`
	Policy          string            `json:"policy"`
	Expected        string            `json:"expected"`
	At              string            `json:"at"`
	TrustAnchorsPEM []string          `json:"trust_anchors_pem"`
	Inputs          polarisMdocInputs `json:"inputs"`
	Response        string            `json:"response"`
	Clauses         []struct {
		Ref string `json:"ref"`
	} `json:"clauses"`
	// Repaired is the same vector with its one defect put back.
	Repaired *struct {
		Inputs   polarisMdocInputs `json:"inputs"`
		Response string            `json:"response"`
	} `json:"repaired"`
}

// polarisMdocInputs is the verifier's own request, from which it builds
// the SessionTranscript and the DCQL query.
type polarisMdocInputs struct {
	ResponseMode  string             `json:"response_mode"`
	ClientID      string             `json:"client_id"`
	Nonce         string             `json:"nonce"`
	ResponseURI   string             `json:"response_uri"`
	Origin        string             `json:"origin"`
	EncryptionJWK json.RawMessage    `json:"encryption_jwk"`
	DoctypeValue  string             `json:"doctype_value"`
	Claims        []dcql.ClaimsQuery `json:"claims"`
	ClaimSets     [][]string         `json:"claim_sets"`
}

// TestPolarisMdocVectors: see the comment above polarisMdocVectorsCommit.
// The controls run first, and the test stops if any is refused: refusals
// measured with a verifier that refuses everything mean nothing. Each
// refusal is followed by its twin.
func TestPolarisMdocVectors(t *testing.T) {
	path := os.Getenv("POLARIS_MDOC_VECTORS")
	if path == "" {
		t.Skip("POLARIS_MDOC_VECTORS is not set: the Polaris vectors workflow sets it to mdoc-vectors.json at polaris-id " + polarisMdocVectorsCommit)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != polarisMdocVectorsSHA256 {
		t.Fatalf("mdoc-vectors.json has SHA-256 %x, want %s (polaris-id %s)", sum, polarisMdocVectorsSHA256, polarisMdocVectorsCommit)
	}
	var file polarisMdocFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}

	var controls, refusals []polarisMdocVector
	for _, v := range file.Vectors {
		switch {
		case v.Class == "control" && v.Expected == "accept":
			controls = append(controls, v)
		case v.Class != "control" && v.Expected == "reject":
			if _, ok := polarisMdocLayerReasons[v.Layer]; !ok {
				t.Errorf("vector %s is at layer %q, which polarisMdocLayerReasons doesn't name: add it", v.ID, v.Layer)
			}
			refusals = append(refusals, v)
		default:
			t.Fatalf("vector %s has class %q and expects %q: a control is accepted, and every other vector refused", v.ID, v.Class, v.Expected)
		}
	}
	if len(controls) == 0 || len(refusals) == 0 {
		t.Fatalf("the file holds %d controls and %d refusals: it measures nothing", len(controls), len(refusals))
	}

	for id := range polarisMdocKnownGaps {
		if !slices.ContainsFunc(refusals, func(v polarisMdocVector) bool { return v.ID == id }) {
			t.Errorf("known gap %q is not a refusal in this file: remove it from polarisMdocKnownGaps", id)
		}
	}
	for name := range polarisMdocPoliciesNotApplied {
		if _, ok := file.Policies[name]; !ok {
			t.Errorf("%q in polarisMdocPoliciesNotApplied is not a policy in this file", name)
		}
	}
	for _, v := range file.Vectors {
		if v.Policy == "" {
			continue
		}
		if _, ok := file.Policies[v.Policy]; !ok {
			t.Errorf("vector %s names policy %q, which the file doesn't define", v.ID, v.Policy)
		}
		if _, notApplied := polarisMdocPoliciesNotApplied[v.Policy]; notApplied {
			if _, listed := polarisMdocKnownGaps[v.ID]; listed {
				t.Errorf("%s is under a policy not applied and in polarisMdocKnownGaps: list it in one", v.ID)
			}
		}
	}

	var passed, gaps, notApplied, twins, failed int
	for _, v := range controls {
		ok := t.Run(v.ID, func(t *testing.T) {
			got, _, why := polarisMdocJudge(t, v.ID, v, v.Inputs, v.Response)
			if got == v.Expected {
				passed++
				t.Logf("pass: %s (%s)", got, why)
				return
			}
			failed++
			t.Errorf("fail: %s, control: judged %q, want %q (%s)", v.ID, got, v.Expected, why)
		})
		if !ok {
			t.Fatalf("control %s was refused: the refusals measure nothing", v.ID)
		}
	}
	for _, v := range refusals {
		t.Run(v.ID, func(t *testing.T) {
			got, reason, why := polarisMdocJudge(t, v.ID, v, v.Inputs, v.Response)
			policyWhy, policyNotApplied := polarisMdocPoliciesNotApplied[v.Policy]
			gap, listed := polarisMdocKnownGaps[v.ID]
			switch {
			case policyNotApplied && got == "accept":
				notApplied++
				t.Logf("policy not applied: %s, policy %s: judged %q, file says %q (%s)", v.ID, v.Policy, got, v.Expected, policyWhy)
			case policyNotApplied:
				failed++
				t.Errorf("fail: %s is now %sed under policy %s, but the policy is in polarisMdocPoliciesNotApplied: remove it from the map (%s)", v.ID, got, v.Policy, why)
			case got == v.Expected && listed:
				failed++
				t.Errorf("fail: %s is now %sed, as the file says, but is in polarisMdocKnownGaps: remove it from the map", v.ID, got)
			case got == v.Expected && !slices.Contains(polarisMdocLayerReasons[v.Layer], reason):
				failed++
				t.Errorf("fail: %s is refused as %s, not as a refusal at layer %s is (%v): it was refused for something else (%s)", v.ID, reason, v.Layer, polarisMdocLayerReasons[v.Layer], why)
			case got == v.Expected:
				passed++
				t.Logf("pass: %s (%s)", got, why)
			case listed:
				gaps++
				t.Logf("known gap: %s, layer %s, %s: judged %q, file says %q (%s)", v.ID, gap.layer, gap.clause, got, v.Expected, gap.note)
			default:
				failed++
				refs := make([]string, len(v.Clauses))
				for i, c := range v.Clauses {
					refs[i] = c.Ref
				}
				t.Errorf("fail: %s, layer %s, %s: judged %q, want %q (%s)", v.ID, v.Layer, strings.Join(refs, "; "), got, v.Expected, why)
			}
		})
		if v.Repaired == nil {
			failed++
			t.Errorf("fail: %s has no repaired twin, so nothing shows its refusal measures something", v.ID)
			continue
		}
		// The corpus changes one thing per vector, so a refused twin means
		// the refusal it pairs with measures nothing.
		t.Run(v.ID+"-repaired", func(t *testing.T) {
			got, _, why := polarisMdocJudge(t, v.ID+" (repaired)", v, v.Repaired.Inputs, v.Repaired.Response)
			if got == "accept" {
				twins++
				t.Logf("pass: twin accepted (%s)", why)
				return
			}
			failed++
			t.Errorf("fail: the repaired twin of %s was refused, so its refusal measures nothing (%s)", v.ID, why)
		})
	}
	t.Logf("vectors %s, polaris-id %s: %d pass, %d known gaps, %d policies not applied, %d twins accepted, %d fail",
		file.Version, polarisMdocVectorsCommit, passed, gaps, notApplied, twins, failed)
}

// polarisMdocJudge gives one response, with the request in inputs, to the
// package and returns "accept" or "reject", the refusal's Reason, and why.
// The trust anchors and the instant are v's. An error that isn't the
// package refusing the presentation (a mistake in this test's own setup)
// fails the test, as does a panic, such as one from the encryption key's
// missing private half below.
func polarisMdocJudge(t *testing.T, name string, v polarisMdocVector, in polarisMdocInputs, response string) (verdict string, reason Reason, why string) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("%s: VerifyResponse panicked: %v", name, p)
		}
	}()
	at, err := time.Parse(time.RFC3339, v.At)
	if err != nil {
		t.Fatalf("%s: at: %v", name, err)
	}
	roots := x509.NewCertPool()
	for _, p := range v.TrustAnchorsPEM {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			t.Fatalf("%s: trust_anchors_pem holds no certificate", name)
		}
	}
	if len(v.TrustAnchorsPEM) == 0 {
		t.Fatalf("%s: trust_anchors_pem is empty", name)
	}

	// The vectors give only the public half of the response encryption
	// key: the responses are given here already decrypted, as
	// ParsedResponse, and on that path VerifyResponse reads
	// ResponseEncryptionKey only for its public key's RFC 7638 thumbprint
	// (verifyMdocPresentation), which the SessionTranscript carries. The
	// private scalar is left unset.
	pub, err := jwk.ParsePublicKey(in.EncryptionJWK)
	if err != nil {
		t.Fatalf("%s: encryption_jwk: %v", name, err)
	}
	encPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("%s: encryption_jwk is a %T, not an EC key", name, pub)
	}

	// The vectors' Client Identifier is a fixed string, not one derived
	// from a certificate this test holds, so the Verifier is built from its
	// parts rather than through New, as in TestPolarisNegativeVectors: cfg
	// and clientID are set here, and deps is left zero, since its Signer
	// and Random serve requests, which this test never builds. If Verifier
	// gains a field, set it here too or leave it zero on purpose.
	cfg := Config{Assurance: AssuranceProduction}
	var origin string
	var expectedOrigins []string
	switch {
	case in.Origin != "" && in.ResponseMode == "dc_api.jwt":
		// A DC API request: the SessionTranscript is built over the origin,
		// and neither the Client Identifier nor response_uri is read.
		origin, expectedOrigins = in.Origin, []string{in.Origin}
	case in.Origin == "" && in.ResponseMode == "direct_post.jwt":
		cfg.ResponseURI, err = fapi.ParseEndpointURL(in.ResponseURI)
		if err != nil {
			t.Fatalf("%s: response_uri: %v", name, err)
		}
		// buildMdocSessionTranscriptBytes uses the parsed URL's String().
		if got := cfg.ResponseURI.String(); got != in.ResponseURI {
			t.Fatalf("%s: response_uri %q reads back as %q", name, in.ResponseURI, got)
		}
	default:
		t.Fatalf("%s: response_mode %q with origin %q is not a request this test knows", name, in.ResponseMode, in.Origin)
	}
	verifier := &Verifier{cfg: cfg, clientID: in.ClientID}

	const queryID = "mdoc"
	cq := dcql.MdocQuery(queryID, in.DoctypeValue)
	cq.Claims, cq.ClaimSets = in.Claims, in.ClaimSets
	query := dcql.Query{Credentials: []dcql.CredentialQuery{cq}}

	result, err := verifier.VerifyResponse(context.Background(), VerifyResponseRequest{
		Query:         query,
		Response:      ParsedResponse{VPToken: map[string][]string{queryID: {response}}},
		ExpectedNonce: in.Nonce,
		// The certificates' CRL distribution point is an .example address that serves no CRL, so the test declines the check.
		MdocIssuerKeys: X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
		// The validity window and the certificates are checked at the
		// vector's instant, with no clock skew.
		Now:                   func() time.Time { return at },
		ResponseEncryptionKey: &ecdsa.PrivateKey{PublicKey: *encPub},
		Origin:                origin,
		ExpectedOrigins:       expectedOrigins,
		// The vectors pin no issuer per type, and test no status: the
		// production decisions are declared, not made.
		AnyIssuerForAnyType: true,
		NoStatusCheck:       true,
	})
	if err != nil {
		var refused *Error
		if !errors.As(err, &refused) {
			t.Fatalf("%s: VerifyResponse failed for a reason other than refusing the presentation: %v", name, err)
		}
		return "reject", refused.Reason(), fmt.Sprintf("%s: %s", refused.Reason(), err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("%s: VerifyResponse accepted %d credentials, want 1", name, len(result.Credentials))
	}
	return "accept", "", "verified"
}
