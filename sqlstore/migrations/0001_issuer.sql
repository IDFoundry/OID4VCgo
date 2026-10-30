-- The issuer's stores. Every record table has the same four columns:
-- id, the record's key; owner, the Credential Issuer that saved it
-- (empty where a record has none); sweep_after, the Unix time after
-- which Sweep deletes it (NULL: never); and record, its encoding.
-- {{key}} is a case-sensitive text type, {{blob}} a binary one, and
-- {name} a table or index name with the DB's prefix.

-- c_nonce values (issuer.NonceStore), keyed by the nonce.
CREATE TABLE {issuer_nonces} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
CREATE INDEX {issuer_nonces_sweep} ON {issuer_nonces} (sweep_after);

-- Pre-authorized codes (issuer.PreAuthorizedCodeStore), keyed by the
-- hash of the code the issuer hands the store; tx_code_hash is the
-- record's own keyed hash of the Transaction Code, and wrong_attempts
-- the wrong guesses so far.
CREATE TABLE {issuer_pre_authorized_codes} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL,
	tx_code_hash {{key}} NOT NULL,
	wrong_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX {issuer_pre_authorized_codes_sweep} ON {issuer_pre_authorized_codes} (sweep_after);

-- Deferred Issuance transactions (issuer.DeferredTransactionStore),
-- keyed by transaction_id.
CREATE TABLE {issuer_deferred_transactions} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
CREATE INDEX {issuer_deferred_transactions_sweep} ON {issuer_deferred_transactions} (sweep_after);

-- notification_id values (issuer.NotificationStore).
CREATE TABLE {issuer_notifications} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
CREATE INDEX {issuer_notifications_sweep} ON {issuer_notifications} (sweep_after);

-- Credential Offers by reference (issuer.CredentialOfferStore), keyed
-- by the reference.
CREATE TABLE {issuer_credential_offers} (
	id {{key}} PRIMARY KEY,
	owner {{key}} NOT NULL,
	sweep_after BIGINT,
	record {{blob}} NOT NULL
);
CREATE INDEX {issuer_credential_offers_sweep} ON {issuer_credential_offers} (sweep_after);
