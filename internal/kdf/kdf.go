package kdf

const (
	DefaultTime    uint32 = 3
	DefaultMemory  uint32 = 64 * 1024
	DefaultThreads uint8  = 4
)

type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func Default() Params {
	return Params{Time: DefaultTime, Memory: DefaultMemory, Threads: DefaultThreads}
}
