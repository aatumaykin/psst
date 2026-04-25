package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultGitHubAPIURL = "https://api.github.com/repos/aatumaykin/psst/releases/latest"

const httpTimeoutSec = 15

var httpClient = &http.Client{Timeout: httpTimeoutSec * time.Second}

func fetchLatestRelease() (*ReleaseInfo, error) {
	return fetchLatestReleaseWithURL(defaultGitHubAPIURL)
}

func fetchLatestReleaseWithURL(apiURL string) (*ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("GitHub API rate limit exceeded. Try again later")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if decodeErr := json.NewDecoder(resp.Body).Decode(&release); decodeErr != nil {
		return nil, fmt.Errorf("decode release: %w", decodeErr)
	}

	if release.TagName == "" {
		return nil, errors.New("release has no tag name")
	}

	return &release, nil
}

func downloadFile(url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("download %s: read body: %w", url, readErr)
	}

	return body, nil
}
