package mobile

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Errors crossing the boundary carry no remote description, URL path or
// query, or control characters, and timeouts and service failures can be
// retried.
func TestClassify(t *testing.T) {
	secretURL := "https://issuer.example/offer?pre-authorized_code=SECRET123"
	for name, tc := range map[string]struct {
		err        error
		code       string
		detail     string
		mustNotSee string
	}{
		"issuer description": {
			err:  fmt.Errorf("walletflow: credential: %w", &wallet.Error{HTTPStatus: 400, Code: "invalid_proof", Description: "JOHN SMITH born 1974\nfake log line"}),
			code: CodeProtocol, detail: "invalid_proof", mustNotSee: "JOHN SMITH",
		},
		"issuer unavailable": {
			err:  &wallet.Error{HTTPStatus: 503, Description: "maintenance"},
			code: CodeUnavailable, mustNotSee: "maintenance",
		},
		"linkable now": {
			err:  fmt.Errorf("walletflow: credential %q: %w", "cred-1", walletflow.ErrLinkable),
			code: CodeInvalidSelection, mustNotSee: "cred-1",
		},
		"refreshed since shown": {
			err:  fmt.Errorf("walletflow: credential %q: %w", "cred-1", walletflow.ErrCredentialChanged),
			code: CodeInvalidSelection, mustNotSee: "cred-1",
		},
		"not configured": {
			err:  fmt.Errorf("walletflow: Config.VerifierTrust is required to present: %w", walletflow.ErrNotConfigured),
			code: CodeInvalidInput, detail: DetailNotConfigured, mustNotSee: "Config.",
		},
		"rate limited": {
			err:  &wallet.Error{HTTPStatus: 429, Code: "slow_down"},
			code: CodeUnavailable, detail: "slow_down",
		},
		"verifier rejection": {
			err:  &wallet.DirectPostRejectedError{StatusCode: 400, Code: "invalid_request", Description: "SECRET123"},
			code: CodeProtocol, detail: "invalid_request", mustNotSee: "SECRET123",
		},
		"authorization denied": {
			err:  &walletflow.AuthorizationDeniedError{Code: "access_denied", Description: "SECRET123"},
			code: CodeAuthorizationDenied, detail: "access_denied", mustNotSee: "SECRET123",
		},
		"network with a URL": {
			err:  fmt.Errorf("walletflow: credential offer: %w", &url.Error{Op: "Get", URL: secretURL, Err: errors.New("connection refused")}),
			code: CodeNetwork, mustNotSee: "SECRET123",
		},
		"timeout": {
			err:  fmt.Errorf("walletflow: nonce: %w", context.DeadlineExceeded),
			code: CodeNetwork,
		},
		"cancelled": {
			err:  fmt.Errorf("walletflow: nonce: %w", context.Canceled),
			code: CodeCancelled,
		},
		"other text with a URL": {
			err:  errors.New("walletflow: the redirect " + secretURL + "\tisn't allowed\n" + strings.Repeat("x", 500)),
			code: CodeProtocol, mustNotSee: "SECRET123",
		},
	} {
		got := classify(tc.err)
		var e *Error
		if !errors.As(got, &e) {
			t.Fatalf("%s: %T", name, got)
		}
		if e.Code != tc.code || e.Detail != tc.detail {
			t.Errorf("%s: [%s:%s], want [%s:%s]", name, e.Code, e.Detail, tc.code, tc.detail)
		}
		if tc.mustNotSee != "" && strings.Contains(e.Message, tc.mustNotSee) {
			t.Errorf("%s: the message carries %q: %s", name, tc.mustNotSee, e.Message)
		}
		if strings.ContainsAny(e.Message, "\n\t") || len([]rune(e.Message)) > maxMessage+1 {
			t.Errorf("%s: the message isn't cleaned: %q", name, e.Message)
		}
	}
}

// A call the configuration lacks what it needs for is invalid_input
// with the not_configured detail, telling it apart from a malformed
// argument, and names NewWallet's keys, not walletflow's fields.
func TestClassify_NotConfigured(t *testing.T) {
	for in, want := range map[string]string{
		"walletflow: Config.VerifierTrust is required to present":                                                     "verifier_roots is required to present",
		"walletflow: Config.IssuerRoots is required to receive credentials":                                           "issuer_roots is required",
		"walletflow: Config.RedirectURI is required to receive credentials with the authorization code grant":         "redirect_uri is required",
		"walletflow: Dependencies.Provider and Config.ClientID are required to receive credentials under ProfileHAIP": `a WalletProvider and client_id are required to receive credentials under "issuance_profile": "haip"`,
	} {
		var e *Error
		if !errors.As(classify(fmt.Errorf("%s: %w", in, walletflow.ErrNotConfigured)), &e) ||
			e.Code != CodeInvalidInput || e.Detail != DetailNotConfigured || !strings.Contains(e.Message, want) {
			t.Errorf("classify(%q) = %#v, want [invalid_input:not_configured] naming %q", in, e, want)
		}
	}
}

func TestCleanText(t *testing.T) {
	got := cleanText("see https://verifier.example/cb?response_code=abc#x and openid-credential-offer://?credential_offer=%7B%7D")
	if got != "see https://verifier.example and openid-credential-offer://" {
		t.Errorf("cleanText = %q", got)
	}
}

// A refresh another process is making with the grant is unavailable,
// retryable, with its own detail.
func TestClassify_RefreshInProgress(t *testing.T) {
	var e *Error
	if !errors.As(classify(fmt.Errorf("walletflow: refresh credential: %w", walletflow.ErrRefreshInProgress)), &e) ||
		e.Code != CodeUnavailable || e.Detail != DetailRefreshInProgress {
		t.Errorf("classify = %#v, want [unavailable:refresh_in_progress]", e)
	}
}

func TestClassify_DeliveryUnknown(t *testing.T) {
	err := fmt.Errorf("walletflow: respond: %w: %w", walletflow.ErrDeliveryUnknown, &url.Error{Op: "Post", URL: "https://verifier.example/r", Err: errors.New("reset")})
	if code(classify(err)) != CodeDeliveryUnknown {
		t.Errorf("classify = %v, want delivery_unknown, not the retryable network", classify(err))
	}
}

// A refused request is request_refused with the OpenID4VP error code
// sent as its detail, and none of the Verifier's own description.
func TestClassify_RequestRefused(t *testing.T) {
	err := classify(&walletflow.RequestRefusedError{Code: "invalid_transaction_data", Description: "the verifier's own words"})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeRequestRefused || e.Detail != "invalid_transaction_data" || strings.Contains(e.Message, "verifier's own words") {
		t.Errorf("classify = %#v", err)
	}
}

// A Wallet Provider callback's network failure, marked by the Swift
// adapter, is network; another failure is platform.
func TestProviderError(t *testing.T) {
	if got := providerError("wallet attestation", errors.New("[network] The Internet connection appears to be offline.")); code(got) != CodeNetwork {
		t.Errorf("a marked network failure: %v", got)
	}
	if got := providerError("key attestation", errors.New("the Wallet Provider refused key-attestation")); code(got) != CodePlatform {
		t.Errorf("a refusal: %v", got)
	}
	if got := providerError("key attestation", context.Canceled); !errors.Is(got, context.Canceled) {
		t.Errorf("a cancellation: %v", got)
	}
}

// A Wallet Provider callback still waiting on the network doesn't hold up
// a cancelled operation.
func TestCancellable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	defer close(release)
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := cancellable(ctx, func() ([]byte, error) { <-release; return []byte("jwt"), nil })
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Errorf("cancellable = %v after %v", err, time.Since(start))
	}
	if jwt, err := cancellable(context.Background(), func() ([]byte, error) { return []byte("jwt"), nil }); err != nil || string(jwt) != "jwt" {
		t.Errorf("cancellable, not cancelled = %q, %v", jwt, err)
	}
}
