//go:build darwin || linux

package gateway

import (
	"errors"
	"os"
	"syscall"
)

func lockSpool(dir string) (*os.File, error) {
	path := dir + string(os.PathSeparator) + ".aegis.lock"
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() || st.Mode()&0077 != 0 {
			return nil, errors.New("unsafe spool lock")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("staging directory is already in use")
	}
	return f, nil
}
