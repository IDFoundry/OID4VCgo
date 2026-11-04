package mdocdcapi

import (
	"context"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// ForTransactions is this package's protocol for verifier.Transactions
// (verifier.TransactionsConfig.MdocDCAPI): Transactions.BeginMdocDCAPI
// builds each request with BuildRequest, signed by readers as
// RequestParams.Readers are, and Transactions.HandleMdocDCAPIResponse
// verifies its response with VerifyResponse. Transactions keeps each
// request's Pending — sealed in its store, bound to the page's browser
// and origin, and answered at most once — and checks its revocation
// status and runs its Accept, which is the bookkeeping BuildRequest and
// VerifyResponse leave to their caller. It refuses a reader key
// BuildRequest would.
func ForTransactions(readers ...ReaderKey) (verifier.MdocDCAPIProtocol, error) {
	for i, r := range readers {
		if _, err := readerauth.CheckKey(r.Signer, r.Chain); err != nil {
			return nil, fmt.Errorf("mdocdcapi: reader %d: %w", i, err)
		}
	}
	return transactionsProtocol{readers: append([]ReaderKey(nil), readers...)}, nil
}

type transactionsProtocol struct{ readers []ReaderKey }

func (p transactionsProtocol) BuildMdocDCAPIRequest(b verifier.MdocDCAPIBuild) (verifier.MdocDCAPIBuilt, error) {
	// Transactions has checked the origin against its Origins, and keeps
	// the request's expiry itself.
	req, err := BuildRequest(RequestParams{
		Origin: b.Origin, DocType: b.DocType, Elements: b.Elements, Readers: p.readers, Random: b.Random, Now: b.Now,
	})
	if err != nil {
		return verifier.MdocDCAPIBuilt{}, err
	}
	return verifier.MdocDCAPIBuilt{
		Data:         verifier.MdocDCAPIRequestData{DeviceRequest: req.Data.DeviceRequest, EncryptionInfo: req.Data.EncryptionInfo},
		RecipientKey: req.Pending.RecipientKey,
	}, nil
}

func (p transactionsProtocol) VerifyMdocDCAPIResponse(ctx context.Context, v verifier.MdocDCAPIVerify) (verifier.VerifiedCredential, error) {
	verified, err := VerifyResponse(ctx, VerifyParams{
		Pending: Pending{
			Origin: v.Origin, DocType: v.DocType, Elements: v.Elements, EncryptionInfo: v.EncryptionInfo,
			RecipientKey: v.RecipientKey, ExpiresAt: v.ExpiresAt,
		},
		Response: v.Response, IssuerKeys: v.IssuerKeys, Now: v.Now, MaxClockSkew: v.MaxClockSkew,
		Assurance: v.Assurance, Origins: v.Origins,
		IssuerAuthorized: v.IssuerAuthorized, AnyIssuerForAnyType: v.AnyIssuerForAnyType,
		// Transactions checks status (TransactionsConfig.Status), so its
		// refusal is reported as its others are.
		NoStatusCheck: true,
	})
	if err != nil {
		return verifier.VerifiedCredential{}, err
	}
	return verified.Credential(), nil
}
