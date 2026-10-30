package sqlstore

// sqliteQueries are the stores' statements for SQLite. A transaction
// starts with BEGIN IMMEDIATE, taking the database's write lock up
// front, so a SELECT in it needs no FOR UPDATE.
var sqliteQueries = queries{ //nolint:gosec // G101: field names such as keyGet are statements, not credentials
	nonceInsert:            "INSERT INTO oid4vc_issuer_nonces (id, owner, sweep_after, record) VALUES (?, ?, ?, ?)",
	nonceConsumeOwned:      "DELETE FROM oid4vc_issuer_nonces WHERE id = ? AND owner = ? RETURNING record",
	nonceSweep:             "DELETE FROM oid4vc_issuer_nonces WHERE sweep_after < ?",
	pacInsert:              "INSERT INTO oid4vc_issuer_pre_authorized_codes (id, owner, sweep_after, record, tx_code_hash) VALUES (?, ?, ?, ?, ?)",
	pacSelectForConsume:    "SELECT tx_code_hash, wrong_attempts, record FROM oid4vc_issuer_pre_authorized_codes WHERE id = ?",
	pacSetAttempts:         "UPDATE oid4vc_issuer_pre_authorized_codes SET wrong_attempts = ? WHERE id = ?",
	pacDelete:              "DELETE FROM oid4vc_issuer_pre_authorized_codes WHERE id = ?",
	pacSweep:               "DELETE FROM oid4vc_issuer_pre_authorized_codes WHERE sweep_after < ?",
	deferredTxInsert:       "INSERT INTO oid4vc_issuer_deferred_transactions (id, owner, sweep_after, record) VALUES (?, ?, ?, ?)",
	deferredTxGet:          "SELECT record FROM oid4vc_issuer_deferred_transactions WHERE id = ?",
	deferredTxGetForUpdate: "SELECT record FROM oid4vc_issuer_deferred_transactions WHERE id = ?",
	deferredTxUpdate:       "UPDATE oid4vc_issuer_deferred_transactions SET owner = ?, sweep_after = ?, record = ? WHERE id = ?",
	deferredTxDelete:       "DELETE FROM oid4vc_issuer_deferred_transactions WHERE id = ?",
	deferredTxSweep:        "DELETE FROM oid4vc_issuer_deferred_transactions WHERE sweep_after < ?",
	notificationInsert:     "INSERT INTO oid4vc_issuer_notifications (id, owner, sweep_after, record) VALUES (?, ?, ?, ?)",
	notificationGet:        "SELECT record FROM oid4vc_issuer_notifications WHERE id = ?",
	notificationSweep:      "DELETE FROM oid4vc_issuer_notifications WHERE sweep_after < ?",
	offerInsert:            "INSERT INTO oid4vc_issuer_credential_offers (id, owner, sweep_after, record) VALUES (?, ?, ?, ?)",
	offerGet:               "SELECT record FROM oid4vc_issuer_credential_offers WHERE id = ?",
	offerSweep:             "DELETE FROM oid4vc_issuer_credential_offers WHERE sweep_after < ?",
	txInsert:               "INSERT INTO oid4vc_verifier_transactions (id, owner, sweep_after, record, key_id, response_code_hash) VALUES (?, ?, ?, ?, ?, ?)",
	txGet:                  "SELECT record FROM oid4vc_verifier_transactions WHERE id = ?",
	txGetForUpdate:         "SELECT record FROM oid4vc_verifier_transactions WHERE id = ?",
	txUpdate:               "UPDATE oid4vc_verifier_transactions SET owner = ?, sweep_after = ?, record = ?, key_id = ?, response_code_hash = ? WHERE id = ?",
	txIDByKeyID:            "SELECT id FROM oid4vc_verifier_transactions WHERE key_id = ?",
	txIDByResponseCode:     "SELECT id FROM oid4vc_verifier_transactions WHERE response_code_hash = ?",
	txSweep:                "DELETE FROM oid4vc_verifier_transactions WHERE sweep_after < ?",
	credentialUpsert:       "INSERT INTO oid4vc_wallet_credentials (id, owner, sweep_after, record) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, sweep_after = excluded.sweep_after, record = excluded.record",
	credentialGet:          "SELECT record FROM oid4vc_wallet_credentials WHERE id = ?",
	credentialGetForUpdate: "SELECT record FROM oid4vc_wallet_credentials WHERE id = ?",
	credentialUpdate:       "UPDATE oid4vc_wallet_credentials SET owner = ?, sweep_after = ?, record = ? WHERE id = ?",
	credentialList:         "SELECT id, record FROM oid4vc_wallet_credentials ORDER BY id",
	credentialDelete:       "DELETE FROM oid4vc_wallet_credentials WHERE id = ?",
	authorizationUpsert:    "INSERT INTO oid4vc_wallet_authorizations (id, owner, sweep_after, record) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, sweep_after = excluded.sweep_after, record = excluded.record",
	authorizationGet:       "SELECT record FROM oid4vc_wallet_authorizations WHERE id = ?",
	authorizationConsume:   "DELETE FROM oid4vc_wallet_authorizations WHERE id = ? RETURNING record",
	authorizationList:      "SELECT id, record FROM oid4vc_wallet_authorizations ORDER BY id",
	authorizationDelete:    "DELETE FROM oid4vc_wallet_authorizations WHERE id = ?",
	authorizationSweep:     "DELETE FROM oid4vc_wallet_authorizations WHERE sweep_after < ?",
	grantUpsert:            "INSERT INTO oid4vc_wallet_grants (id, owner, sweep_after, record) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, sweep_after = excluded.sweep_after, record = excluded.record",
	grantGet:               "SELECT record FROM oid4vc_wallet_grants WHERE id = ?",
	grantGetForUpdate:      "SELECT record FROM oid4vc_wallet_grants WHERE id = ?",
	grantUpdate:            "UPDATE oid4vc_wallet_grants SET owner = ?, sweep_after = ?, record = ? WHERE id = ?",
	grantList:              "SELECT id, record FROM oid4vc_wallet_grants ORDER BY id",
	grantDelete:            "DELETE FROM oid4vc_wallet_grants WHERE id = ?",
	deferredUpsert:         "INSERT INTO oid4vc_wallet_deferred (id, owner, sweep_after, record) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET owner = excluded.owner, sweep_after = excluded.sweep_after, record = excluded.record",
	deferredList:           "SELECT id, record FROM oid4vc_wallet_deferred ORDER BY id",
	deferredDelete:         "DELETE FROM oid4vc_wallet_deferred WHERE id = ?",
	keyInsert:              "INSERT INTO oid4vc_wallet_keys (id, owner, sweep_after, record) VALUES (?, ?, ?, ?)",
	keyGet:                 "SELECT record FROM oid4vc_wallet_keys WHERE id = ?",
	keyDelete:              "DELETE FROM oid4vc_wallet_keys WHERE id = ?",
	migrationsCreate:       "CREATE TABLE IF NOT EXISTS oid4vc_schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
	migrationApplied:       "SELECT 1 FROM oid4vc_schema_migrations WHERE version = ?",
	migrationRecord:        "INSERT INTO oid4vc_schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
	migrationVersions:      "SELECT version FROM oid4vc_schema_migrations",
}

// The statements of a SQLite write transaction (DB.write).
const (
	// sqliteBusyTimeout has a connection wait up to 10 seconds for
	// another's write lock before failing.
	sqliteBusyTimeout = "PRAGMA busy_timeout = 10000"
	sqliteBegin       = "BEGIN IMMEDIATE"
	sqliteCommit      = "COMMIT"
	sqliteRollback    = "ROLLBACK"
)
