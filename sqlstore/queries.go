package sqlstore

// queries are every statement the stores run, written out for one
// dialect: sqliteQueries with ? placeholders, postgresQueries with $n,
// each with its dialect's own locking (Postgres's FOR UPDATE). Every one
// is a string literal, so no statement is built at run time; a
// test checks the two sets name the same tables and take the same
// arguments.
//
// Table names are fixed: on PostgreSQL, deployments sharing a database
// keep apart with a schema each (search_path), and on SQLite with a
// file each.
type queries struct {
	// oid4vc_issuer_nonces: issuer.NonceStore.
	nonceInsert, nonceConsumeOwned, nonceSweep string

	// oid4vc_issuer_pre_authorized_codes: issuer.PreAuthorizedCodeStore.
	pacInsert, pacSelectForConsume, pacSetAttempts, pacDelete, pacSweep string

	// oid4vc_issuer_deferred_transactions: issuer.DeferredTransactionStore.
	deferredTxInsert, deferredTxGet, deferredTxGetForUpdate, deferredTxUpdate, deferredTxDelete, deferredTxSweep string

	// oid4vc_issuer_notifications: issuer.NotificationStore.
	notificationInsert, notificationGet, notificationSweep string

	// oid4vc_issuer_credential_offers: issuer.CredentialOfferStore.
	offerInsert, offerGet, offerSweep string

	// oid4vc_verifier_transactions: verifier.TransactionStore.
	txInsert, txGet, txGetForUpdate, txUpdate, txIDByKeyID, txIDByResponseCode, txSweep string

	// oid4vc_wallet_credentials: walletflow.CredentialStore.
	credentialUpsert, credentialGet, credentialGetForUpdate, credentialUpdate, credentialList, credentialDelete string

	// oid4vc_wallet_authorizations: walletflow.AuthorizationStore.
	authorizationUpsert, authorizationGet, authorizationConsume, authorizationList, authorizationDelete, authorizationSweep string

	// oid4vc_wallet_grants: walletflow.GrantStore.
	grantUpsert, grantGet, grantGetForUpdate, grantUpdate, grantList, grantDelete string

	// oid4vc_wallet_deferred: walletflow.DeferredStore.
	deferredUpsert, deferredList, deferredDelete string

	// oid4vc_wallet_keys: KeyStore.
	keyInsert, keyGet, keyDelete string

	// oid4vc_schema_migrations: Migrate and CheckSchema.
	migrationsCreate, migrationApplied, migrationRecord, migrationVersions string
}
