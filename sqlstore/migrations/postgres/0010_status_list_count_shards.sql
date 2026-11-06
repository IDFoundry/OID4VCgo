-- statuslist.IndexStore.Reserved: a list's count of reserved indices is
-- now kept in 32 shards, an index counted in shard idx % 32, and summed
-- on read. The trigger of 0007 added each reservation to the list's one
-- row of oid4vc_status_list_counts, which stayed locked until the
-- reservation committed, so every Reserve of a list waited for the one
-- before it; indices being drawn at random, concurrent Reserves now
-- mostly update different shards. Each list's count moves to its shard
-- 0, with oid4vc_status_indices locked meanwhile, so no reservation is
-- counted in neither.
--
-- oid4vc_status_list_counts becomes a view summing the shards, so an
-- older release, running beside this one, still counts a list's
-- reserved indices; its Delete fails at the view, leaving the list
-- counted for this release's Delete to finish.
LOCK TABLE oid4vc_status_indices IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE oid4vc_status_list_count_shards (
	uri TEXT COLLATE "C" NOT NULL,
	shard SMALLINT NOT NULL CHECK (shard BETWEEN 0 AND 31),
	reserved BIGINT NOT NULL CHECK (reserved >= 0),
	PRIMARY KEY (uri, shard)
);
INSERT INTO oid4vc_status_list_count_shards (uri, shard, reserved)
	SELECT uri, 0, reserved FROM oid4vc_status_list_counts;
CREATE OR REPLACE FUNCTION oid4vc_status_indices_counted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO oid4vc_status_list_count_shards (uri, shard, reserved) VALUES (NEW.uri, NEW.idx % 32, 1)
		ON CONFLICT (uri, shard) DO UPDATE SET reserved = oid4vc_status_list_count_shards.reserved + 1;
	RETURN NULL;
END
$$;
DROP TABLE oid4vc_status_list_counts;
CREATE VIEW oid4vc_status_list_counts AS
	SELECT uri, CAST(SUM(reserved) AS BIGINT) AS reserved FROM oid4vc_status_list_count_shards GROUP BY uri;
