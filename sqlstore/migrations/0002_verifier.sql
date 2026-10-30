-- The verifier's presentation transactions (verifier.TransactionStore),
-- keyed by transaction ID. record is verifier.TransactionCodec's
-- encoding, sealed by its own Sealer if it has one; owner is the
-- Transaction's Owner, sweep_after its RetainUntil, and key_id and
-- response_code_hash the columns its lookups go by ('' for none).
CREATE TABLE {verifier_transactions} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL,
	key_id {{key}} NOT NULL,
	response_code_hash {{key}} NOT NULL
);
CREATE INDEX {verifier_transactions_sweep} ON {verifier_transactions} (sweep_after);
CREATE UNIQUE INDEX {verifier_transactions_key_id} ON {verifier_transactions} (key_id) WHERE key_id <> '';
CREATE UNIQUE INDEX {verifier_transactions_response_code_hash} ON {verifier_transactions} (response_code_hash) WHERE response_code_hash <> '';
