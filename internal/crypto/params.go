package crypto

import "github.com/aatumaykin/psst/internal/kdf"

type KDFParams = kdf.Params

func DefaultKDFParams() KDFParams {
	return kdf.Default()
}
