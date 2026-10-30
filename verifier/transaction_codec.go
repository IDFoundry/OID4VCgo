package verifier

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// TransactionCodecVersion is the version of the encoding
// TransactionCodec writes, recorded in each record. Unmarshal refuses
// any other.
const TransactionCodecVersion = 1

// TransactionCodec encodes a Transaction for a TransactionStore that
// keeps it outside the process — a database row, a cache entry — so a
// store needn't define its own encoding of each field. Marshal records
// every field, Unmarshal restores it as it was: a credential's claims
// keep their types (an mdoc element's integer, byte string or date
// stays one), and the response decryption key comes back usable. A
// store that indexes transactions (by KeyID and ResponseCodeHash, and
// by RetainUntil to delete them) reads those from the Transaction
// itself and keeps them beside the encoded record.
//
// A transaction holds two things worth protecting where it's stored:
// the response decryption key, which opens the holder's answer, and,
// once the request completes, the claims the holder disclosed (Result).
// With Sealer set, both are sealed, each bound to the transaction's ID,
// so a copy of the store reveals neither and one transaction's sealed
// fields can't be moved to another's. Set it wherever the store is
// shared, backed up or readable by more than the Verifier: AESGCMSealer
// is one, with a key the Verifier keeps outside the store. The rest of
// the record — the request's nonce and state, which its public Request
// Object carries, the browser binding's and response_code's hashes,
// the query — stays readable, so a store can index and expire records
// without the key. TransactionsConfig.ForgetResultOnRead drops the
// claims once they've been read, so the store holds them for as little
// time as possible.
//
// The zero TransactionCodec seals nothing.
type TransactionCodec struct {
	// Sealer, if set, seals the response decryption key and Result.
	// Unmarshal then refuses a record whose fields aren't sealed, and a
	// codec without one refuses a record whose are: a store that starts
	// sealing doesn't read the records it wrote before — at most
	// TransactionsConfig.Lifetime's worth, twice over.
	Sealer TransactionSealer
}

// TransactionSealer seals and opens a Transaction's secret fields for
// TransactionCodec — an AEAD, such as AESGCMSealer, or a call to a key
// management service. Open must refuse sealed data altered in any way,
// or sealed with other additionalData: that's what binds each sealed
// field to its transaction.
type TransactionSealer interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(sealed, additionalData []byte) ([]byte, error)
}

// AESGCMSealer is a TransactionSealer that seals with AES-256-GCM
// under key (32 bytes, from a cryptographically secure source, kept
// outside the store), with a random nonce for each seal. Changing the
// key makes the records sealed under the previous one unreadable; to
// rotate it, open with both until those records expire, with a
// TransactionSealer of your own.
func AESGCMSealer(key []byte) (TransactionSealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("verifier: transaction sealer: key is %d bytes, want 32 (AES-256)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("verifier: transaction sealer: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("verifier: transaction sealer: %w", err)
	}
	return gcmSealer{aead}, nil
}

type gcmSealer struct{ aead cipher.AEAD }

func (s gcmSealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plaintext)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (s gcmSealer) Open(sealed, additionalData []byte) ([]byte, error) {
	if len(sealed) < s.aead.NonceSize() {
		return nil, errors.New("sealed data is too short")
	}
	nonce, ciphertext := sealed[:s.aead.NonceSize()], sealed[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, ciphertext, additionalData)
}

// wireTransaction is a Transaction as TransactionCodec records it.
type wireTransaction struct {
	Version            int               `json:"v"`
	ID                 string            `json:"id"`
	KeyID              string            `json:"kid,omitempty"`
	State              string            `json:"state,omitempty"`
	Nonce              string            `json:"nonce,omitempty"`
	Query              dcql.Query        `json:"query"`
	Sealed             bool              `json:"sealed,omitempty"`
	DecryptionKey      []byte            `json:"response_decryption_key,omitempty"`
	RequestObject      string            `json:"request_object,omitempty"`
	Origin             string            `json:"origin,omitempty"`
	Owner              string            `json:"owner,omitempty"`
	BrowserBindingHash []byte            `json:"browser_binding_hash,omitempty"`
	SameDevice         bool              `json:"same_device,omitempty"`
	ExpiresAt          time.Time         `json:"expires_at"`
	RetainUntil        time.Time         `json:"retain_until"`
	Status             TransactionStatus `json:"status"`
	ResponseCodeHash   string            `json:"response_code_hash,omitempty"`
	Result             json.RawMessage   `json:"result,omitempty"`
	SealedResult       []byte            `json:"sealed_result,omitempty"`
	LastError          string            `json:"last_error,omitempty"`
}

// wireResult is a VerifyResponseResult as TransactionCodec records it.
type wireResult struct {
	Credentials []wireCredential        `json:"credentials"`
	Discarded   []DiscardedPresentation `json:"discarded,omitempty"`
}

// wireCredential is a VerifiedCredential: an SD-JWT VC's claims as the
// JSON they came from, an mdoc's (and its status reference) as CBOR,
// so each keeps the types its own format decodes to.
type wireCredential struct {
	CredentialQueryID string          `json:"credential_query_id"`
	Claims            json.RawMessage `json:"claims,omitempty"`
	MdocClaims        []byte          `json:"mdoc_claims,omitempty"`
	MdocStatus        []byte          `json:"mdoc_status,omitempty"`
	IssuerChain       [][]byte        `json:"issuer_chain,omitempty"`
}

// Marshal encodes tx, sealing its secret fields with c.Sealer if set.
func (c TransactionCodec) Marshal(tx Transaction) ([]byte, error) {
	w := wireTransaction{
		Version: TransactionCodecVersion, ID: tx.ID, KeyID: tx.KeyID, State: tx.State, Nonce: tx.Nonce, Query: tx.Query,
		Sealed: c.Sealer != nil, RequestObject: tx.RequestObject, Origin: tx.Origin, Owner: tx.Owner,
		BrowserBindingHash: tx.BrowserBindingHash, SameDevice: tx.SameDevice, ExpiresAt: tx.ExpiresAt, RetainUntil: tx.RetainUntil,
		Status: tx.Status, ResponseCodeHash: tx.ResponseCodeHash, LastError: tx.LastError,
	}
	if tx.ResponseDecryptionKey != nil {
		der, err := x509.MarshalPKCS8PrivateKey(tx.ResponseDecryptionKey)
		if err != nil {
			return nil, fmt.Errorf("verifier: marshal transaction: response decryption key: %w", err)
		}
		if w.DecryptionKey, err = c.seal(der, "response_decryption_key", tx.ID); err != nil {
			return nil, err
		}
	}
	if tx.Result != nil {
		result, err := marshalResult(*tx.Result, tx.Query)
		if err != nil {
			return nil, fmt.Errorf("verifier: marshal transaction: result: %w", err)
		}
		if c.Sealer == nil {
			w.Result = result
		} else if w.SealedResult, err = c.seal(result, "result", tx.ID); err != nil {
			return nil, err
		}
	}
	return json.Marshal(w)
}

// Unmarshal decodes a record Marshal wrote, opening its sealed fields
// with c.Sealer.
func (c TransactionCodec) Unmarshal(data []byte) (Transaction, error) {
	var w wireTransaction
	if err := strictjson.Unmarshal(data, &w); err != nil {
		return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wireTransaction{}); err != nil {
		return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: %w", err)
	}
	switch {
	case w.Version != TransactionCodecVersion:
		return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: version %d, want %d", w.Version, TransactionCodecVersion)
	case w.ID == "":
		return Transaction{}, errors.New("verifier: unmarshal transaction: no id")
	case w.Status < TransactionPending || w.Status > TransactionClosed:
		return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: status %d isn't one a store holds", w.Status)
	case w.Sealed != (c.Sealer != nil):
		return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: the record is sealed: %t, and the codec has a sealer: %t", w.Sealed, c.Sealer != nil)
	}
	tx := Transaction{
		ID: w.ID, KeyID: w.KeyID, State: w.State, Nonce: w.Nonce, Query: w.Query, RequestObject: w.RequestObject,
		Origin: w.Origin, Owner: w.Owner, BrowserBindingHash: w.BrowserBindingHash, SameDevice: w.SameDevice,
		ExpiresAt: w.ExpiresAt, RetainUntil: w.RetainUntil, Status: w.Status, ResponseCodeHash: w.ResponseCodeHash, LastError: w.LastError,
	}
	if w.DecryptionKey != nil {
		der, err := c.open(w.DecryptionKey, "response_decryption_key", w.ID)
		if err != nil {
			return Transaction{}, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: response decryption key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: response decryption key is a %T, want an EC key", key)
		}
		tx.ResponseDecryptionKey = ecKey
	}
	result := []byte(w.Result)
	if w.SealedResult != nil {
		opened, err := c.open(w.SealedResult, "result", w.ID)
		if err != nil {
			return Transaction{}, err
		}
		result = opened
	}
	if result != nil {
		r, err := unmarshalResult(result, w.Query)
		if err != nil {
			return Transaction{}, fmt.Errorf("verifier: unmarshal transaction: result: %w", err)
		}
		tx.Result = &r
	}
	return tx, nil
}

// sealAD binds a sealed field to its name and its transaction's ID.
func sealAD(field, id string) []byte {
	return []byte("oid4vcgo verifier transaction v1\x00" + field + "\x00" + id)
}

func (c TransactionCodec) seal(plaintext []byte, field, id string) ([]byte, error) {
	if c.Sealer == nil {
		return plaintext, nil
	}
	sealed, err := c.Sealer.Seal(plaintext, sealAD(field, id))
	if err != nil {
		return nil, fmt.Errorf("verifier: marshal transaction: seal %s: %w", field, err)
	}
	return sealed, nil
}

func (c TransactionCodec) open(sealed []byte, field, id string) ([]byte, error) {
	if c.Sealer == nil {
		return sealed, nil
	}
	plaintext, err := c.Sealer.Open(sealed, sealAD(field, id))
	if err != nil {
		return nil, fmt.Errorf("verifier: unmarshal transaction: open %s: %w", field, err)
	}
	return plaintext, nil
}

// formats maps each of query's credential query IDs to its format,
// which says how a verified credential's claims are encoded.
func formats(query dcql.Query) map[string]string {
	out := make(map[string]string, len(query.Credentials))
	for _, cq := range query.Credentials {
		out[cq.ID] = cq.Format
	}
	return out
}

func marshalResult(r VerifyResponseResult, query dcql.Query) ([]byte, error) {
	byID := formats(query)
	w := wireResult{Credentials: make([]wireCredential, 0, len(r.Credentials)), Discarded: r.Discarded}
	for _, vc := range r.Credentials {
		wc := wireCredential{CredentialQueryID: vc.CredentialQueryID, IssuerChain: vc.IssuerChain}
		var err error
		switch byID[vc.CredentialQueryID] {
		case mdoc.CredentialFormat:
			if wc.MdocClaims, err = claimsEncMode.Marshal(vc.Claims); err == nil && vc.MdocStatus != nil {
				wc.MdocStatus, err = claimsEncMode.Marshal(vc.MdocStatus)
			}
		case "":
			err = fmt.Errorf("credential query %q isn't in the transaction's query", vc.CredentialQueryID)
		default:
			wc.Claims, err = json.Marshal(vc.Claims)
		}
		if err != nil {
			return nil, err
		}
		w.Credentials = append(w.Credentials, wc)
	}
	return json.Marshal(w)
}

func unmarshalResult(data []byte, query dcql.Query) (VerifyResponseResult, error) {
	var w wireResult
	if err := strictjson.Unmarshal(data, &w); err != nil {
		return VerifyResponseResult{}, err
	}
	byID := formats(query)
	r := VerifyResponseResult{Credentials: make([]VerifiedCredential, 0, len(w.Credentials)), Discarded: w.Discarded}
	for _, wc := range w.Credentials {
		vc := VerifiedCredential{CredentialQueryID: wc.CredentialQueryID, IssuerChain: wc.IssuerChain}
		var err error
		switch byID[wc.CredentialQueryID] {
		case mdoc.CredentialFormat:
			vc.Claims, vc.MdocStatus, err = unmarshalMdocClaims(wc.MdocClaims, wc.MdocStatus)
		case "":
			err = fmt.Errorf("credential query %q isn't in the transaction's query", wc.CredentialQueryID)
		default:
			// As sdjwtvc.Verify decodes them: numbers as float64.
			err = strictjson.Unmarshal(wc.Claims, &vc.Claims)
		}
		if err != nil {
			return VerifyResponseResult{}, err
		}
		r.Credentials = append(r.Credentials, vc)
	}
	return r, nil
}

func unmarshalMdocClaims(claimsCBOR, statusCBOR []byte) (map[string]any, *mdoc.Status, error) {
	var nameSpaces map[string]map[string]any
	if err := claimsDecMode.Unmarshal(claimsCBOR, &nameSpaces); err != nil {
		return nil, nil, err
	}
	claims := make(map[string]any, len(nameSpaces))
	for ns, elements := range nameSpaces {
		claims[ns] = elements
	}
	if statusCBOR == nil {
		return claims, nil, nil
	}
	status := new(mdoc.Status)
	if err := claimsDecMode.Unmarshal(statusCBOR, status); err != nil {
		return nil, nil, err
	}
	return claims, status, nil
}

// claimsEncMode and claimsDecMode carry an mdoc's claims as its own
// decoding gave them: a tdate as a time.Time under tag 0, any other tag
// (a full-date's 1004) as the cbor.Tag it decoded to.
var (
	claimsEncMode = func() cbor.EncMode {
		mode, err := cbor.EncOptions{Time: cbor.TimeRFC3339Nano, TimeTag: cbor.EncTagRequired}.EncMode()
		if err != nil {
			panic(fmt.Sprintf("verifier: build CBOR encoder: %v", err))
		}
		return mode
	}()
	claimsDecMode = func() strictcbor.DecMode {
		mode, err := cbor.DecOptions{
			TimeTag: cbor.DecTagRequired, DupMapKey: cbor.DupMapKeyEnforcedAPF, FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
			MaxNestedLevels: mdoc.MaxCBORNestedLevels + 2, MaxArrayElements: mdoc.MaxCBORContainerItems, MaxMapPairs: mdoc.MaxCBORContainerItems,
		}.DecMode()
		if err != nil {
			panic(fmt.Sprintf("verifier: build CBOR decoder: %v", err))
		}
		return strictcbor.Wrap(mode)
	}()
)
