# Sourced by the interop scripts: builds OID4VCgo's side as a
# deployment runs it.
#
# cmd/conformance-issuer's and cmd/conformance-verifier's production
# setups (production assurance over sealed sqlstore stores), and
# interop/walletprovider's Wallet Provider, keep their records in
# sqlstore, a module of its own that the root module doesn't require:
# they build only with the conformance_production tag, in a Go
# workspace holding both modules. The workspace is written to the run's
# own directory, never to the checkout.

# build_production builds each package into $1 under the
# conformance_production tag, from the checkout $2: "name=package"
# pairs (an output name and a package), e.g. verifier=./cmd/conformance-verifier.
build_production() {  # $1 output directory, $2 checkout; then name=package pairs
  local out="$1" src="$2" pair
  shift 2
  mkdir -p "$out/gowork"
  rm -f "$out/gowork/go.work" "$out/gowork/go.work.sum"
  (cd "$out/gowork" && GOWORK=off go work init "$src" "$src/sqlstore")
  for pair in "$@"; do
    (cd "$src" && GOWORK="$out/gowork/go.work" go build -tags conformance_production -o "$out/${pair%%=*}" "${pair#*=}")
  done
}

# sealing_key prints a fresh base64 AES-256-GCM key, a production
# setup's sealing_key.
sealing_key() {
  openssl rand -base64 32
}

# access_token_key prints a fresh P-256 private key, SEC 1 PEM: a production
# issuer's access_token_signing_key_pem.
access_token_key() {
  openssl ecparam -name prime256v1 -genkey -noout
}

# start_wallet_provider starts interop/walletprovider's provider (the
# binary $1, from build_production) in the background, on loopback port
# $3 as https://localhost:$3, its admin listener on loopback port $4,
# attesting client $5, writing its CA (ca.pem), TLS certificate
# (tls-cert.pem), database and log to $2; the rest are its flags. The
# caller takes its PID from $!.
start_wallet_provider() {  # $1 binary, $2 dir, $3 port, $4 admin port, $5 client_id; then flags
  local bin="$1" dir="$2" port="$3" admin="$4" client="$5"
  shift 5
  mkdir -p "$dir"
  "$bin" -dir "$dir" -addr "127.0.0.1:$port" -base-url "https://localhost:$port" \
    -admin "127.0.0.1:$admin" -client-id "$client" "$@" > "$dir/wallet-provider.log" 2>&1 &
}

# start_provider_agent starts the wallet's side of the provider at
# https://localhost:$3, from the same binary $1, on loopback port $4, as
# one registered instance, trusting the TLS certificate the provider
# wrote to $2; it logs to $2/agent.log. The caller takes its PID from $!.
start_provider_agent() {  # $1 binary, $2 the provider's dir, $3 its port, $4 the agent's port
  "$1" agent -provider "https://localhost:$3" -tls-cert "$2/tls-cert.pem" -addr "127.0.0.1:$4" > "$2/agent.log" 2>&1 &
}

# wait_ready waits for each URL to answer, failing the run if one
# doesn't within 10 s; https ones are fetched without verifying their
# certificate (readiness, not trust).
wait_ready() {  # URLs
  local url
  for url in "$@"; do
    for _ in $(seq 1 50); do
      if curl -sk -o /dev/null --max-time 1 "$url"; then continue 2; fi
      sleep 0.2
    done
    echo "$url did not start" >&2
    return 1
  done
}
