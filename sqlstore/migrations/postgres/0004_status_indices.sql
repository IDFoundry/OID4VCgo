-- statuslist.IndexStore: the Status List indices a statuslist.Allocator
-- has handed out, one row per (uri, idx), and each one's status. A row
-- is never deleted, since an index once handed out is never handed out
-- again, and nothing here expires. The primary key is what makes a
-- reservation atomic: of concurrent INSERTs of one (uri, idx), one
-- inserts the row.
CREATE TABLE oid4vc_status_indices (
	uri TEXT COLLATE "C" NOT NULL,
	idx BIGINT NOT NULL CHECK (idx >= 0),
	status SMALLINT NOT NULL DEFAULT 0 CHECK (status BETWEEN 0 AND 255),
	PRIMARY KEY (uri, idx)
);
