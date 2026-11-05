-- walletprovider.InstanceKeyStore: an instance key's sweep_after is now
-- its record's RetainUntil, which Create and Update store, so Sweep
-- deletes the keys no wallet has used for the provider's retention; a
-- row from before keeps NULL, never swept, until its key next moves.
-- The index serves Sweep's DELETE … WHERE sweep_after < ?, as each
-- record table's own does.
CREATE INDEX oid4vc_walletprovider_instance_keys_sweep ON oid4vc_walletprovider_instance_keys (sweep_after);
