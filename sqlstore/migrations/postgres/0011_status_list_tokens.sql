-- statuslist.TokenStore: the Status List Tokens the replicas serving a
-- list share, so that one of them signs a list's token at a time and
-- the others serve it.
--
-- oid4vc_status_list_versions holds each list's version, which a
-- trigger raises in the transaction that changes one of the list's
-- statuses: a token signed from an older version is signed anew. A
-- list none of whose statuses has changed has no row, its version zero.
--
-- oid4vc_status_list_tokens holds, for each list and form (0 for the
-- JWT, 1 for the CWT), the latest token, the version it was signed
-- from, when it was signed and expires, and the lease on signing the
-- next one: the replica named lease_holder signs it, until lease_until.
-- Times are Unix milliseconds. A row whose lease was taken before any
-- token was stored has no token.
CREATE TABLE oid4vc_status_list_versions (
	uri TEXT COLLATE "C" PRIMARY KEY,
	version BIGINT NOT NULL CHECK (version >= 0)
);
CREATE TABLE oid4vc_status_list_tokens (
	uri TEXT COLLATE "C" NOT NULL,
	form SMALLINT NOT NULL CHECK (form IN (0, 1)),
	token BYTEA,
	version BIGINT NOT NULL DEFAULT 0,
	signed_at BIGINT NOT NULL DEFAULT 0,
	exp BIGINT NOT NULL DEFAULT 0,
	lease_holder TEXT,
	lease_until BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (uri, form)
);
CREATE FUNCTION oid4vc_status_indices_versioned() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO oid4vc_status_list_versions (uri, version) VALUES (NEW.uri, 1)
		ON CONFLICT (uri) DO UPDATE SET version = oid4vc_status_list_versions.version + 1;
	RETURN NULL;
END
$$;
CREATE TRIGGER oid4vc_status_indices_versioned AFTER UPDATE OF status ON oid4vc_status_indices
	FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION oid4vc_status_indices_versioned();
