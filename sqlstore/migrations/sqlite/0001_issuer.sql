-- The issuer's stores. Every record table has the same four columns:
-- id, the record's key; owner, the Credential Issuer that saved it
-- (empty where a record has none); sweep_after, the Unix time after
-- which Sweep deletes it (NULL: never); and record, its encoding.
-- IDs compare case-sensitively: bytewise (TEXT is BINARY).

-- c_nonce values (issuer.NonceStore), keyed by the nonce.
CREATE TABLE oid4vc_issuer_nonces (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL
);
CREATE INDEX oid4vc_issuer_nonces_sweep ON oid4vc_issuer_nonces (sweep_after);

-- Pre-authorized codes (issuer.PreAuthorizedCodeStore), keyed by the
-- hash of the code the issuer hands the store; tx_code_hash is the
-- record's own keyed hash of the Transaction Code, and wrong_attempts
-- the wrong guesses so far.
CREATE TABLE oid4vc_issuer_pre_authorized_codes (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL,
	tx_code_hash TEXT NOT NULL,
	wrong_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX oid4vc_issuer_pre_authorized_codes_sweep ON oid4vc_issuer_pre_authorized_codes (sweep_after);

-- Deferred Issuance transactions (issuer.DeferredTransactionStore),
-- keyed by transaction_id.
CREATE TABLE oid4vc_issuer_deferred_transactions (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL
);
CREATE INDEX oid4vc_issuer_deferred_transactions_sweep ON oid4vc_issuer_deferred_transactions (sweep_after);

-- notification_id values (issuer.NotificationStore).
CREATE TABLE oid4vc_issuer_notifications (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL
);
CREATE INDEX oid4vc_issuer_notifications_sweep ON oid4vc_issuer_notifications (sweep_after);

-- Credential Offers by reference (issuer.CredentialOfferStore), keyed
-- by the reference.
CREATE TABLE oid4vc_issuer_credential_offers (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL
);
CREATE INDEX oid4vc_issuer_credential_offers_sweep ON oid4vc_issuer_credential_offers (sweep_after);
