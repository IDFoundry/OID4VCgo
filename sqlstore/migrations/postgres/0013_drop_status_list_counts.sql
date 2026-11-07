-- 0010 left oid4vc_status_list_counts as a view summing
-- oid4vc_status_list_count_shards, so a release from before it, running
-- beside a later one, still counted a list's reserved indices. No
-- release reading it runs beside this one, so the view goes.
DROP VIEW oid4vc_status_list_counts;
