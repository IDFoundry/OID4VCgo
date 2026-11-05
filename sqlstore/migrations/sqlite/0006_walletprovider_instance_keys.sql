-- walletprovider.InstanceKeyStore: the instance keys a Wallet Provider
-- has recorded, keyed by the key's RFC 7638 thumbprint, with the four
-- columns of every record table (see 0001_issuer.sql); owner is unused
-- (''), and sweep_after is NULL: an instance key never expires, its
-- status list index being reserved for good. The primary key makes
-- Create's check and store one INSERT, so one key belongs to one
-- instance across every process. instance_id is the instance the key
-- belongs to; its index serves List's walk over one instance's keys in
-- thumbprint order.
CREATE TABLE oid4vc_walletprovider_instance_keys (
	id TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	sweep_after BIGINT,
	record BLOB NOT NULL,
	instance_id TEXT NOT NULL
);
CREATE INDEX oid4vc_walletprovider_instance_keys_instance ON oid4vc_walletprovider_instance_keys (instance_id, id);
