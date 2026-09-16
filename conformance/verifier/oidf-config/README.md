# conformance-verifier oidf-config

`haip.config.json` (and any other config this directory ever needs)
is never committed — it embeds private key material (see the root
`.gitignore`). Generate it locally:

```
go run ./conformance/verifier/scripts/generate-config \
  -out=conformance/verifier/oidf-config/haip.config.json \
  -base-url=https://conformance-verifier:8443
```

The command also prints (to stderr) the JWK to paste into the OIDF
suite's own "Credential Issuer" > "Signing JWK" test-configuration
field when creating a test plan for
`oid4vp-1final-verifier-haip-test-plan` ("OpenID for Verifiable
Presentations 1.0 Final/HAIP: Test a verifier") — the suite signs its
own emulated test credentials with that key, and this binary needs to
trust the matching public key to verify them (`credential_issuer_jwk`
in the generated config).

Re-run `generate-config` any time; every value it produces is
throwaway and safe to discard/regenerate.
