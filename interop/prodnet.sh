# shellcheck shell=bash
# Sourced by the interop scripts for their production-assurance legs:
# OID4VCgo's wallet at production assurance (walletflow's Development
# false, wallet's and fapigo/client's AssuranceProduction), talking to
# the other side's services as it would to a deployment's.
#
# Production's HTTP client dials public addresses only, besides the
# private addresses of hosts the wallet is configured to allow
# (walletflow.Config.AllowedPrivateHosts, wallet.Config.Fetch's and
# fapihttp.TransportConfig's), as a deployment whose services are
# inside its own network configures it; loopback stays refused. These
# legs run the wallet, built for Linux, in a container on a network of
# their own (prodnet_create): internal, so nothing on it has a route
# out, on a private subnet Docker assigns. The other side's
# containers are attached to it under the names their URLs carry
# (prodnet_attach), and the wallet is given exactly those names to
# allow, so every other private address, and every name that isn't
# theirs, is still refused. The wallet's TLS roots are the system's,
# which the container reads from SSL_CERT_FILE: the run's TLS CA. Those
# roots and the allowed names are what a deployment on a private
# network configures too; nothing else is relaxed: the wallet's client
# is the one production builds, and its stores are sqlstore's
# (internal/prodwallet). A CRL
# publisher the wallet runs in its own process for its revocation
# checks stays on its loopback, as internal/conformancecrl documents.

# The image the wallet runs in: static binaries, nothing else.
PRODNET_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# prodnet_build SRC OUT PKG...: builds each PKG, with the Go release
# SRC/go.mod names, for the Docker host's Linux, with the
# conformance_production tag (internal/prodwallet's sqlstore stores),
# in a Go workspace holding SRC and SRC/sqlstore, into OUT/NAME-linux.
prodnet_build() {
  local src="$1" out="$2"; shift 2
  local arch work gover
  arch="$(docker version -f '{{.Server.Arch}}')"
  # The Go release go.mod names, as CI builds with: a newer one's
  # standard library can hide what this one refuses.
  gover="$(sed -nE 's/^go ([0-9.]+)$/\1/p' "$src/go.mod")"
  work="$out/prodnet-go.work"
  rm -f "$work"
  (cd "$out" && GOWORK=off GOTOOLCHAIN="go$gover" go work init "$src" "$src/sqlstore" && mv go.work "$work")
  local pkg
  for pkg in "$@"; do
    (cd "$src" && GOWORK="$work" GOTOOLCHAIN="go$gover" CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
      go build -tags conformance_production -o "$out/$(basename "$pkg")-linux" "$pkg")
  done
}

# prodnet_create NAME: the internal network, on a subnet Docker assigns
# from its private address pools.
prodnet_create() {
  local name="$1"
  docker network rm "$name" >/dev/null 2>&1 || true
  docker network create --internal "$name" >/dev/null
}

# prodnet_subnet NAME: the network's subnet, for the logs.
prodnet_subnet() {
  docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$1" | xargs
}

# prodnet_attach NAME CONTAINER ALIAS...: connects CONTAINER to the
# network, reachable there as each ALIAS.
prodnet_attach() {
  local name="$1" container="$2"; shift 2
  local args=() a
  for a in "$@"; do args+=(--alias "$a"); done
  docker network connect "${args[@]}" "$name" "$container"
}

# prodnet_run NAME DIR CA CONTAINER ARGS...: runs ARGS (the first a
# binary in DIR) in a container named CONTAINER on the network, DIR
# mounted at /work and the working directory, trusting DIR/CA as the
# system's TLS roots, as this user (so its files are this user's).
prodnet_run() {
  local name="$1" dir="$2" ca="$3" container="$4" binary="$5"; shift 5
  docker run --rm --name "$container" --network "$name" \
    --user "$(id -u):$(id -g)" -v "$dir:/work" -w /work \
    -e SSL_CERT_FILE="/work/$ca" -e SSL_CERT_DIR=/nonexistent \
    --entrypoint "/work/$binary" "$PRODNET_IMAGE" "$@"
}

# prodnet_start NAME DIR CA CONTAINER PUBLISH ARGS...: prodnet_run, for
# a server: detached, its port published as PUBLISH (docker run's -p)
# through a network of its own, NAME-front, which the script reaches it
# by and which carries no alias of the other side's, so every name the
# wallet resolves to the other side is on NAME.
prodnet_start() {
  local name="$1" dir="$2" ca="$3" container="$4" publish="$5" binary="$6"; shift 6
  docker network inspect "$name-front" >/dev/null 2>&1 || docker network create "$name-front" >/dev/null
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker create --name "$container" --network "$name-front" -p "$publish" \
    --user "$(id -u):$(id -g)" -v "$dir:/work" -w /work \
    -e SSL_CERT_FILE="/work/$ca" -e SSL_CERT_DIR=/nonexistent \
    --entrypoint "/work/$binary" "$PRODNET_IMAGE" "$@" >/dev/null
  docker network connect "$name" "$container"
  docker start "$container" >/dev/null
}

# prodnet_remove NAME: removes the network, and NAME-front, disconnecting
# what's on them.
prodnet_remove() {
  local name="$1" n c
  for n in "$name" "$name-front"; do
    for c in $(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$n" 2>/dev/null); do
      docker network disconnect -f "$n" "$c" >/dev/null 2>&1 || true
    done
    docker network rm "$n" >/dev/null 2>&1 || true
  done
}
