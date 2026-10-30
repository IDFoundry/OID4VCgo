-- The verifier's presentation transactions (verifier.TransactionStore),
-- keyed by transaction ID. record is verifier.TransactionCodec's
-- encoding, sealed by its own Sealer if it has one; owner is the
-- Transaction's Owner, sweep_after its RetainUntil, and key_id and
-- response_code_hash the columns its lookups go by ('' for none).
CREATE TABLE oid4vc_verifier_transactions (
	id TEXT COLLATE "C" PRIMARY KEY,
	owner TEXT COLLATE "C" NOT NULL,
	sweep_after BIGINT,
	record BYTEA NOT NULL,
	key_id TEXT COLLATE "C" NOT NULL,
	response_code_hash TEXT COLLATE "C" NOT NULL
);
CREATE INDEX oid4vc_verifier_transactions_sweep ON oid4vc_verifier_transactions (sweep_after);
CREATE UNIQUE INDEX oid4vc_verifier_transactions_key_id ON oid4vc_verifier_transactions (key_id) WHERE key_id <> '';
CREATE UNIQUE INDEX oid4vc_verifier_transactions_response_code_hash ON oid4vc_verifier_transactions (response_code_hash) WHERE response_code_hash <> '';
