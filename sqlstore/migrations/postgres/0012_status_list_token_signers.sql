-- statuslist.TokenStore: the signer of each stored Status List Token,
-- the SHA-256 of its leaf certificate, so that a replica serves a
-- stored token only when it signs with the same certificate. A token
-- stored before this migration has none, and is signed anew once.
ALTER TABLE oid4vc_status_list_tokens ADD COLUMN signer BYTEA NOT NULL DEFAULT ''::bytea;
