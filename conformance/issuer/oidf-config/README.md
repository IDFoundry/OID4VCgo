# conformance-issuer oidf-config

`haip.config.json` is never committed — it embeds private key material
(see the root `.gitignore`). Generate it locally:

```
go run ./conformance/issuer/scripts/generate-config \
  -issuer=https://conformance-issuer:8443 \
  -out=conformance/issuer/oidf-config/haip.config.json
```

Then fill in the generated config's `client` object (`id`,
`redirect_uris`, `expected_attester_issuer`) from whatever the OIDF
suite's own test-configuration UI assigns when you create a test plan
for `oid4vci-1_0-issuer-haip-test-plan`.

Every other value the generator produces is throwaway and safe to
discard/regenerate. See `../README.md`'s own "Open questions" for what
else is still unconfirmed about the suite's own exact config
expectations.
