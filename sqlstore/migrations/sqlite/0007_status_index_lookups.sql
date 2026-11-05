-- statuslist.IndexStore's two reads of a whole list, made cheap for a
-- list of millions of indices. Reserved, which statuslist.Allocator
-- calls on every Allocate, reads a list's count of reserved indices
-- from oid4vc_status_list_counts, kept by a trigger on every inserted
-- row (none is ever deleted), rather than counting the rows. Statuses
-- reads the rows with a status other than 0 through a partial index,
-- which holds only those, rather than every row of the list.
CREATE TABLE oid4vc_status_list_counts (
	uri TEXT PRIMARY KEY,
	reserved INTEGER NOT NULL CHECK (reserved >= 0)
) WITHOUT ROWID;
INSERT INTO oid4vc_status_list_counts (uri, reserved)
	SELECT uri, COUNT(*) FROM oid4vc_status_indices GROUP BY uri;
CREATE TRIGGER oid4vc_status_indices_counted AFTER INSERT ON oid4vc_status_indices
BEGIN
	INSERT INTO oid4vc_status_list_counts (uri, reserved) VALUES (NEW.uri, 1)
		ON CONFLICT (uri) DO UPDATE SET reserved = reserved + 1;
END;
CREATE INDEX oid4vc_status_indices_set ON oid4vc_status_indices (uri, idx, status) WHERE status <> 0;
