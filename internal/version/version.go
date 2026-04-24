package version

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go"`
	OSArch    string `json:"os_arch"`
}

func String() string {
	return fmt.Sprintf("psst %s\ncommit: %s\nbuilt:  %s\ngo:     %s\nos/arch: %s/%s",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func JSON() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OSArch:    runtime.GOOS + "/" + runtime.GOARCH,
	}
}
