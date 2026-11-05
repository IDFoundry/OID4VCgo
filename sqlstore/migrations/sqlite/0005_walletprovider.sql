-- walletprovider's stores, each with the four columns of every record
-- table (see 0001_issuer.sql); owner is unused ('').
--
-- Registered wallet instances (walletprovider.InstanceStore), keyed by
-- the instance's ID. key_thumbprint is the instance key's RFC 7638
-- thumbprint, UNIQUE as id is, so one INSERT checks that neither is
-- registered and registers both; revision is the record's Revision,
-- which an UPDATE compares and increments. sweep_after is NULL:
-- instances never expire.
CREATE TABLE oid4vc_walletprovider_instances (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL,
	key_thumbprint TEXT NOT NULL UNIQUE,
	revision INTEGER NOT NULL CHECK (revision >= 1)
);

-- Issued challenges (walletprovider.ChallengeStore), keyed by the
-- challenge value; sweep_after is the challenge's ExpiresAt.
CREATE TABLE oid4vc_walletprovider_challenges (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL
);
CREATE INDEX oid4vc_walletprovider_challenges_sweep ON oid4vc_walletprovider_challenges (sweep_after);
