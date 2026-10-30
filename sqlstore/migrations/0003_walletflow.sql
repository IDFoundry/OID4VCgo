-- walletflow's stores: a wallet's credentials, authorizations in
-- progress, refresh grants, pending deferred credentials and keys, each
-- keyed by its ID (an authorization by its state). owner is unused
-- (''); sweep_after is an authorization's ExpiresAt, and NULL for the
-- rest, which walletflow deletes itself.
CREATE TABLE {wallet_credentials} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);

CREATE TABLE {wallet_authorizations} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
CREATE INDEX {wallet_authorizations_sweep} ON {wallet_authorizations} (sweep_after);

CREATE TABLE {wallet_grants} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);

CREATE TABLE {wallet_deferred} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);

-- Keys are always sealed: a DB without a Sealer has no KeyStore.
CREATE TABLE {wallet_keys} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
