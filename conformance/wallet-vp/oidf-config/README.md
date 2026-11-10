# conformance-wallet-vp oidf-config

`haip.config.json` is never committed — it embeds private key material
(see the root `.gitignore`). Generate it locally:

```
go run ./conformance/wallet-vp/scripts/generate-config \
  -out=conformance/wallet-vp/oidf-config/haip.config.json
```

Every value it produces is throwaway and safe to discard/regenerate.
The OIDF suite's own `credential.trust_anchor_pem` field takes the CA
certificate the credential-issuer key's certificate was issued under,
not that leaf (see `../README.md`).
