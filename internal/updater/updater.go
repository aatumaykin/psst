package updater

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/aatumaykin/psst/internal/version"
)

type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
	ChecksumURL    string
	AssetName      string
}

type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckForUpdate() (*UpdateInfo, error) {
	release, err := fetchLatestRelease()
	if err != nil {
		return nil, fmt.Errorf("check for update: %w", err)
	}

	currentVer := strings.TrimPrefix(version.Version, "v")
	latestVer := strings.TrimPrefix(release.TagName, "v")

	assetName := buildAssetName(release.TagName, runtime.GOOS, runtime.GOARCH)

	var downloadURL, checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.URL
		}
		if asset.Name == "checksums.txt" {
			checksumURL = asset.URL
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	return &UpdateInfo{
		CurrentVersion: currentVer,
		LatestVersion:  latestVer,
		DownloadURL:    downloadURL,
		ChecksumURL:    checksumURL,
		AssetName:      assetName,
	}, nil
}

func (u *UpdateInfo) IsNewer() bool {
	return compareVersions(u.LatestVersion, u.CurrentVersion) > 0
}

func buildAssetName(tag, goos, goarch string) string {
	ver := strings.TrimPrefix(tag, "v")
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("psst_%s_%s_%s%s", ver, goos, goarch, ext)
}

func compareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aParts := strings.SplitN(a, "-", 2) //nolint:mnd // split into version and prerelease
	bParts := strings.SplitN(b, "-", 2) //nolint:mnd // split into version and prerelease

	cmp := compareVersionParts(aParts[0], bParts[0])
	if cmp != 0 {
		return cmp
	}

	aPre := ""
	bPre := ""
	if len(aParts) > 1 {
		aPre = aParts[1]
	}
	if len(bParts) > 1 {
		bPre = bParts[1]
	}

	if aPre == "" && bPre == "" {
		return 0
	}
	if aPre == "" {
		return 1
	}
	if bPre == "" {
		return -1
	}
	aPri := prereleasePriority(aPre)
	bPri := prereleasePriority(bPre)
	if aPri != bPri {
		if aPri < bPri {
			return -1
		}
		return 1
	}
	return 0
}

var prereleaseOrder = map[string]int{
	"dev":   0,
	"alpha": 1,
	"beta":  2,
	"rc":    3,
}

func prereleasePriority(s string) int {
	lower := strings.ToLower(s)
	for prefix, prio := range prereleaseOrder {
		if strings.HasPrefix(lower, prefix) {
			return prio
		}
	}
	return 0
}

func compareVersionParts(a, b string) int {
	aNums := strings.Split(a, ".")
	bNums := strings.Split(b, ".")

	maxLen := max(len(aNums), len(bNums))

	for i := range maxLen {
		aVal := 0
		bVal := 0
		if i < len(aNums) {
			aVal, _ = strconv.Atoi(aNums[i])
		}
		if i < len(bNums) {
			bVal, _ = strconv.Atoi(bNums[i])
		}
		if aVal != bVal {
			if aVal < bVal {
				return -1
			}
			return 1
		}
	}
	return 0
}
