package updater

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func PerformUpdate(info *UpdateInfo, force bool) error {
	if !force && !info.IsNewer() {
		return fmt.Errorf("already up to date (v%s)", info.CurrentVersion)
	}

	checksumData, err := downloadFile(info.ChecksumURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}

	archiveData, err := downloadFile(info.DownloadURL)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	checksums, err := parseChecksums(checksumData)
	if err != nil {
		return fmt.Errorf("parse checksums: %w", err)
	}

	if err := verifyChecksum(checksums, info.AssetName, archiveData); err != nil {
		return fmt.Errorf("verify checksum: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "psst-update-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.AssetName)
	if err := os.WriteFile(archivePath, archiveData, 0o644); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}

	binaryData, err := extractBinaryFromTarGz(archivePath)
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	if runtime.GOOS == "windows" {
		return fmt.Errorf("windows update not yet supported via tar.gz extraction")
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current binary: %w", err)
	}

	newBinaryPath := filepath.Join(tmpDir, "psst-new")
	if err := os.WriteFile(newBinaryPath, binaryData, 0o755); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}

	if err := replaceBinary(currentExe, newBinaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}

	return nil
}

func extractBinaryFromTarGz(archivePath string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		if hdr.Name == "psst" || filepath.Base(hdr.Name) == "psst" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read binary from tar: %w", err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("binary 'psst' not found in archive")
}

func replaceBinary(currentPath, newPath string) error {
	if err := os.Chmod(newPath, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	backupPath := currentPath + ".bak"
	if err := os.Rename(currentPath, backupPath); err != nil {
		if err := copyFile(newPath, currentPath); err != nil {
			return fmt.Errorf("copy over current binary: %w", err)
		}
		return os.Remove(newPath)
	}

	if err := os.Rename(newPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		return fmt.Errorf("rename new binary: %w", err)
	}

	_ = os.Remove(backupPath)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}
