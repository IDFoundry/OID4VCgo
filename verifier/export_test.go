package verifier

// MarshalTransactionVersion is c.Marshal writing a record of an older
// version, as an earlier release wrote it, to test that it still opens.
func MarshalTransactionVersion(c TransactionCodec, tx Transaction, version int) ([]byte, error) {
	return c.marshal(tx, version)
}
