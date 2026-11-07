-- walletprovider.InstanceStore.Create: an instance's CredentialID (an
-- App Attest key's key ID) registers one instance, as its key
-- thumbprint does. credential_id is NULL for an instance without one
-- (Android's) and for every instance registered before: a UNIQUE index
-- allows any number of NULLs, so one INSERT checks that no other
-- instance has the ID and registers it. A release from before, running
-- beside this one, inserts NULL.
ALTER TABLE oid4vc_walletprovider_instances ADD COLUMN credential_id TEXT;
CREATE UNIQUE INDEX oid4vc_walletprovider_instances_credential_id ON oid4vc_walletprovider_instances (credential_id);
