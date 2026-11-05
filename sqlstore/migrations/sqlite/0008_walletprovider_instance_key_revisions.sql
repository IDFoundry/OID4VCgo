-- walletprovider.InstanceKeyStore.Update: an instance key's record
-- changes when the key moves to a later period's status lists. revision
-- is the record's Revision, which an UPDATE compares and increments, as
-- oid4vc_walletprovider_instances' does. A row from before starts at
-- 1, as Create stores, and its record, which has no Revision, is read
-- as at 1.
ALTER TABLE oid4vc_walletprovider_instance_keys ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1);
