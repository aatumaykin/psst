package updater

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const maxBinarySize = 100 * 1024 * 1024

func PerformUpdate(info *UpdateInfo, force bool) error {
	if !force && !info.IsNewer() {
		return fmt.Errorf("already up to date (v%s)", info.CurrentVersion)
	}

	checksumData, err := downloadFile(info.ChecksumURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}

	archiveData, archiveErr := downloadFile(info.DownloadURL)
	if archiveErr != nil {
		return fmt.Errorf("download archive: %w", archiveErr)
	}

	checksums := parseChecksums(checksumData)

	if verifyErr := verifyChecksum(checksums, info.AssetName, archiveData); verifyErr != nil {
		return fmt.Errorf("verify checksum: %w", verifyErr)
	}

	tmpDir, tmpErr := os.MkdirTemp("", "psst-update-*")
	if tmpErr != nil {
		return fmt.Errorf("create temp dir: %w", tmpErr)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.AssetName)
	if writeErr := os.WriteFile(archivePath, archiveData, 0o600); writeErr != nil {
		return fmt.Errorf("write archive: %w", writeErr)
	}

	binaryData, extractErr := extractBinaryFromTarGz(archivePath)
	if extractErr != nil {
		return fmt.Errorf("extract binary: %w", extractErr)
	}

	if runtime.GOOS == "windows" {
		return errors.New("windows update not yet supported via tar.gz extraction")
	}

	currentExe, exeErr := os.Executable()
	if exeErr != nil {
		return fmt.Errorf("find current binary: %w", exeErr)
	}

	newBinaryPath := filepath.Join(tmpDir, "psst-new")
	//nolint:gosec // executable binary needs execute permission
	if binErr := os.WriteFile(newBinaryPath, binaryData, 0o755); binErr != nil {
		return fmt.Errorf("write new binary: %w", binErr)
	}

	if replaceErr := replaceBinary(currentExe, newBinaryPath); replaceErr != nil {
		return fmt.Errorf("replace binary: %w", replaceErr)
	}

	return nil
}

func extractBinaryFromTarGz(archivePath string) ([]byte, error) {
	f, openErr := os.Open(archivePath)
	if openErr != nil {
		return nil, fmt.Errorf("open archive: %w", openErr)
	}
	defer f.Close()

	gz, gzErr := gzip.NewReader(f)
	if gzErr != nil {
		return nil, fmt.Errorf("gzip reader: %w", gzErr)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("read tar: %w", nextErr)
		}

		if hdr.Name == "psst" || filepath.Base(hdr.Name) == "psst" {
			if hdr.Size > maxBinarySize {
				return nil, fmt.Errorf("binary in archive too large: %d bytes", hdr.Size)
			}
			data, readErr := io.ReadAll(io.LimitReader(tr, maxBinarySize))
			if readErr != nil {
				return nil, fmt.Errorf("read binary from tar: %w", readErr)
			}
			return data, nil
		}
	}

	return nil, errors.New("binary 'psst' not found in archive")
}

func replaceBinary(currentPath, newPath string) error {
	if chmodErr := os.Chmod(newPath, 0o755); chmodErr != nil { //nolint:gosec // binary must be executable
		return fmt.Errorf("chmod new binary: %w", chmodErr)
	}

	backupPath := currentPath + ".bak"
	backupCreated := false
	if renameErr := os.Rename(currentPath, backupPath); renameErr == nil {
		backupCreated = true
	}

	if moveErr := os.Rename(newPath, currentPath); moveErr != nil {
		if copyErr := copyFile(newPath, currentPath); copyErr != nil {
			if backupCreated {
				_ = os.Rename(backupPath, currentPath)
			}
			return fmt.Errorf("copy over current binary: %w", copyErr)
		}
	}

	if backupCreated {
		_ = os.Remove(backupPath)
	}
	return nil
}

func copyFile(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, copyErr := io.Copy(out, in); copyErr != nil {
		return copyErr
	}

	return out.Sync()
}
