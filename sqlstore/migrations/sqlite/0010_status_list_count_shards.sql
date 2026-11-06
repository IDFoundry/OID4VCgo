-- statuslist.IndexStore.Reserved: a list's count of reserved indices is
-- now kept in 32 shards, an index counted in shard idx % 32, and summed
-- on read. On Postgres, the trigger of 0007 added each reservation to
-- the list's one row of oid4vc_status_list_counts, which stayed locked
-- until the reservation committed, so every Reserve of a list waited
-- for the one before it. SQLite has one writer anyway, so the shards
-- change nothing here but keep the two schemas alike. Each list's count
-- moves to its shard 0.
--
-- oid4vc_status_list_counts becomes a view summing the shards, so an
-- older release, running beside this one, still counts a list's
-- reserved indices; its Delete fails at the view, leaving the list
-- counted for this release's Delete to finish.
CREATE TABLE oid4vc_status_list_count_shards (
	uri TEXT NOT NULL,
	shard INTEGER NOT NULL CHECK (shard BETWEEN 0 AND 31),
	reserved INTEGER NOT NULL CHECK (reserved >= 0),
	PRIMARY KEY (uri, shard)
) WITHOUT ROWID;
INSERT INTO oid4vc_status_list_count_shards (uri, shard, reserved)
	SELECT uri, 0, reserved FROM oid4vc_status_list_counts;
DROP TRIGGER oid4vc_status_indices_counted;
CREATE TRIGGER oid4vc_status_indices_counted AFTER INSERT ON oid4vc_status_indices
BEGIN
	INSERT INTO oid4vc_status_list_count_shards (uri, shard, reserved) VALUES (NEW.uri, NEW.idx % 32, 1)
		ON CONFLICT (uri, shard) DO UPDATE SET reserved = reserved + 1;
END;
DROP TABLE oid4vc_status_list_counts;
CREATE VIEW oid4vc_status_list_counts AS
	SELECT uri, CAST(SUM(reserved) AS BIGINT) AS reserved FROM oid4vc_status_list_count_shards GROUP BY uri;
