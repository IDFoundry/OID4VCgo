# OID4VCIgo

[![CI](https://github.com/IDFoundry/OID4VCIgo/actions/workflows/ci.yml/badge.svg)](https://github.com/IDFoundry/OID4VCIgo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**OpenID4VCI 1.0 + OpenID4VP 1.0, under the HAIP 1.0 profile, for Go.**

OID4VCIgo is a sister library to [FAPIgo](https://github.com/IDFoundry/FAPIgo),
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

> **⚠ Very early stage.** This repository currently has no protocol
> packages — see [ARCHITECTURE.md](ARCHITECTURE.md) for the planned
> package layout and its current status. Not usable yet.

See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the exact specification and
Internet-Draft versions this project targets — every one of them was
verified against the spec's own published/status text and, for drafts,
the exact `draft-…-NN` a Final OIDF spec pins, rather than assumed.

```
go get github.com/idfoundry/oid4vcigo
```

*(Go module paths are lowercased; the GitHub repository itself is
[IDFoundry/OID4VCIgo](https://github.com/IDFoundry/OID4VCIgo).)*

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
