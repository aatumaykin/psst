package crypto

const (
	// KDFVersion1 is the legacy SHA-256 key derivation.
	KDFVersion1 = 1
	// KDFVersion2 is the current Argon2id key derivation.
	KDFVersion2 = 2

	// CurrentKDFVersion is the KDF version used for new vaults.
	CurrentKDFVersion = KDFVersion2
)
