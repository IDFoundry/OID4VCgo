# conformance-wallet-vp oidf-config

`haip.config.json` is never committed — it embeds private key material
(see the root `.gitignore`). Generate it locally:

```
go run ./conformance/wallet-vp/scripts/generate-config \
  -out=conformance/wallet-vp/oidf-config/haip.config.json
```

Every value it produces is throwaway and safe to discard/regenerate.
See `../README.md`'s own "Open questions" for what's still unconfirmed
about what to paste into the OIDF suite's own credential-trust
test-configuration field.
