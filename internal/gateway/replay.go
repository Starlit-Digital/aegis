package gateway

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func grantPath(dir, id string) string { return filepath.Join(filepath.Dir(dir), "grant-"+id+".used") }
func loadGrants(root string, now time.Time) (map[string]time.Time, error) {
	result := map[string]time.Time{}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "grant-") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "grant-"), ".used")
		if !strings.HasSuffix(name, ".used") || !identifier.MatchString(id) {
			return nil, errors.New("invalid replay ledger")
		}
		path := filepath.Join(root, name)
		st, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !st.Mode().IsRegular() || st.Mode()&0077 != 0 || st.Size() != 8 {
			return nil, errors.New("unsafe replay ledger")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		expiry := time.Unix(int64(binary.BigEndian.Uint64(b)), 0)
		if !now.Before(expiry) {
			if e = os.Remove(path); e != nil {
				return nil, e
			}
			continue
		}
		result[id] = expiry
		if len(result) > 1024 {
			return nil, errors.New("replay ledger exceeds ceiling")
		}
	}
	return result, nil
}
func burnGrant(dir, id string, expires int64) error {
	f, e := os.OpenFile(grantPath(dir, id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	b := binary.BigEndian.AppendUint64(nil, uint64(expires))
	if _, e = f.Write(b); e != nil {
		return e
	}
	return f.Sync()
}
