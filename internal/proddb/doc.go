// Package proddb opens the database the conformance and interop
// binaries' production setups keep their sqlstore and fapigo/sqlstore
// records in, a SQLite file or a PostgreSQL database, and sweeps it as
// a deployment's instances do. It takes both database drivers, which
// the root module doesn't require, so it builds only with the
// conformance_production tag, in a Go workspace holding this module
// and ./sqlstore (interop/production.sh's build_production).
package proddb
