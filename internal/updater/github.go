package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultGitHubAPIURL = "https://api.github.com/repos/aatumaykin/psst/releases/latest"

var httpClient = &http.Client{Timeout: 15 * time.Second}

func fetchLatestRelease() (*ReleaseInfo, error) {
	return fetchLatestReleaseWithURL(defaultGitHubAPIURL)
}

func fetchLatestReleaseWithURL(apiURL string) (*ReleaseInfo, error) {
	resp, err := httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub API rate limit exceeded. Try again later")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}

	if release.TagName == "" {
		return nil, fmt.Errorf("release has no tag name")
	}

	return &release, nil
}

func downloadFile(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, err)
	}

	return body, nil
}
