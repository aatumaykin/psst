package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func parseChecksums(data []byte) map[string]string {
	checksums := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2) //nolint:mnd // checksum format: hash  filename
		if len(parts) != 2 {                   //nolint:mnd // exactly 2 parts expected
			continue
		}
		checksums[parts[1]] = parts[0]
	}
	return checksums
}

func verifyChecksum(checksums map[string]string, filename string, data []byte) error {
	expected, ok := checksums[filename]
	if !ok {
		return fmt.Errorf("no checksum found for %s", filename)
	}

	h := sha256.Sum256(data)
	actual := hex.EncodeToString(h[:])

	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filename, expected, actual)
	}

	return nil
}
