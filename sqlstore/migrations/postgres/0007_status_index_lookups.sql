-- statuslist.IndexStore's two reads of a whole list, made cheap for a
-- list of millions of indices. Reserved, which statuslist.Allocator
-- calls on every Allocate, reads a list's count of reserved indices
-- from oid4vc_status_list_counts, kept by a trigger on every inserted
-- row (none is ever deleted), rather than counting the rows. Statuses
-- reads the rows with a status other than 0 through a partial index,
-- which holds only those, rather than every row of the list.
--
-- CREATE INDEX blocks writes to oid4vc_status_indices while it builds:
-- on a large table, that is some seconds of Reserve and SetStatus
-- waiting.
CREATE TABLE oid4vc_status_list_counts (
	uri TEXT COLLATE "C" PRIMARY KEY,
	reserved BIGINT NOT NULL CHECK (reserved >= 0)
);
INSERT INTO oid4vc_status_list_counts (uri, reserved)
	SELECT uri, COUNT(*) FROM oid4vc_status_indices GROUP BY uri;
CREATE FUNCTION oid4vc_status_indices_counted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	INSERT INTO oid4vc_status_list_counts (uri, reserved) VALUES (NEW.uri, 1)
		ON CONFLICT (uri) DO UPDATE SET reserved = oid4vc_status_list_counts.reserved + 1;
	RETURN NULL;
END
$$;
CREATE TRIGGER oid4vc_status_indices_counted AFTER INSERT ON oid4vc_status_indices
	FOR EACH ROW EXECUTE FUNCTION oid4vc_status_indices_counted();
CREATE INDEX oid4vc_status_indices_set ON oid4vc_status_indices (uri, idx) INCLUDE (status) WHERE status <> 0;
