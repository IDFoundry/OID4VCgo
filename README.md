# OID4VCgo

[![CI](https://github.com/IDFoundry/OID4VCgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/OID4VCgo/actions/workflows/ci.yml)
[![OID4VC Conformance](https://github.com/IDFoundry/OID4VCgo/actions/workflows/conformance.yml/badge.svg)](https://github.com/IDFoundry/OID4VCgo/actions/workflows/conformance.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=IDFoundry_OID4VCgo)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=coverage)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=IDFoundry_OID4VCgo&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=IDFoundry_OID4VCgo)

**OpenID4VCI 1.0 + OpenID4VP 1.0, under the HAIP 1.0 profile, for Go.**

OID4VCgo is a sister library to [FAPIgo](https://github.com/IDFoundry/FAPIgo),
targeting the full [OpenID4VC High Assurance Interoperability Profile
(HAIP) 1.0][haip] — the OpenID Foundation's interoperability profile for
digital credential issuance and presentation where a high level of
security and privacy is required (e.g. mobile driving licences and other
government-grade digital identity credentials). HAIP profiles two base
specifications — [OpenID for Verifiable Credential Issuance 1.0][oid4vci]
and [OpenID for Verifiable Presentations 1.0][oid4vp] — and requires
compliance with the applicable provisions of FAPI 2.0 Security Profile
Final, the same security profile FAPIgo implements and is OpenID
Certified™ against.

This isn't a generic, profile-agnostic OID4VCI/OID4VP implementation
with HAIP as an optional layer on top: HAIP's overrides — DPoP
mandatory, Wallet Attestation in place of `private_key_jwt`/mTLS, HAIP's
own algorithm requirements — are unconditional in the `issuer`/`wallet`/
`verifier` packages themselves. See ARCHITECTURE.md's "Relationship to
FAPIgo" section for the specific list.

> **⚠ Pre-1.0, APIs may still change.** Every role package — `issuer`,
> `wallet`, `verifier`, `credential/sdjwtvc`, `credential/mdoc`,
> `statuslist`, `attestation`, `dcql`, `oid4vpmdoc`, `haip`, `storage` —
> is implemented and tested, and all four `cmd/conformance-*` binaries
> have been run live against a real OIDF conformance suite instance.
> See [ARCHITECTURE.md](ARCHITECTURE.md) for the full package-by-package
> status and what, if anything, remains.

See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the exact specification and
Internet-Draft versions this project targets — every one of them was
verified against the spec's own published/status text and, for drafts,
the exact `draft-…-NN` a Final OIDF spec pins, rather than assumed.

```
go get github.com/idfoundry/oid4vcgo
```

*(Go module paths are lowercased; the GitHub repository itself is
[IDFoundry/OID4VCgo](https://github.com/IDFoundry/OID4VCgo).)*

## Relevant specifications

- [OpenID for Verifiable Credential Issuance 1.0][oid4vci]
- [OpenID for Verifiable Presentations 1.0][oid4vp]
- [OpenID4VC High Assurance Interoperability Profile 1.0][haip]
- [FAPI 2.0 Security Profile][fapi2]

See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the complete list,
including the pinned credential-format, attestation, and status-list
Internet-Drafts.

[oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[haip]: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
[fapi2]: https://openid.net/specs/fapi-security-profile-2_0.html

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conformance-first
development philosophy and pre-PR checklist, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).

OpenID®, OpenID Connect™, and OpenID Certified™ are trademarks or
registered trademarks of the OpenID Foundation in the United States and
other countries.
