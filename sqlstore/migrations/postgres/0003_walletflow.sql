-- walletflow's stores: a wallet's credentials, authorizations in
-- progress, refresh grants, pending deferred credentials and keys, each
-- keyed by its ID (an authorization by its state). owner is unused
-- (''); sweep_after is an authorization's ExpiresAt, and NULL for the
-- rest, which walletflow deletes itself.
CREATE TABLE oid4vc_wallet_credentials (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL
);

CREATE TABLE oid4vc_wallet_authorizations (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL
);
CREATE INDEX oid4vc_wallet_authorizations_sweep ON oid4vc_wallet_authorizations (sweep_after);

CREATE TABLE oid4vc_wallet_grants (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL
);

CREATE TABLE oid4vc_wallet_deferred (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL
);

-- Keys are always sealed: a DB without a Sealer has no KeyStore.
CREATE TABLE oid4vc_wallet_keys (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL
);
