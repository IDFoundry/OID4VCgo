# conformance-issuer oidf-config

`haip.config.json` is never committed — it embeds private key material
(see the root `.gitignore`). `conformance/issuer/scripts/run-fapi2sp-battery`
generates it, client blocks included, on every run. To write one by
hand instead:

```
go run ./conformance/issuer/scripts/generate-config \
  -issuer=https://conformance-issuer:8443 \
  -client2 \
  -out=conformance/issuer/oidf-config/haip.config.json
```

`-client2` emits the `client2` block, which
`oid4vci-1_0-issuer-haip-test-plan` needs (even its `happy-flow`
module). Then fill in the generated config's `client` and `client2`
objects (`id`, `redirect_uris`, `expected_attester_issuer`, and the
attester's public keys in `attester_jwks` — or, to verify its `x5c`
chain instead, its CA in `attester_trust_anchors_pem`) from whatever the OIDF suite's own
test-configuration UI assigns when you create a test plan for
`oid4vci-1_0-issuer-haip-test-plan`.

Every other value the generator produces is throwaway and safe to
discard/regenerate.
