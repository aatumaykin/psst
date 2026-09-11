package crypto

type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func DefaultKDFParams() KDFParams {
	return KDFParams{Time: argon2Iterations, Memory: argon2Memory, Threads: argon2Threads}
}
