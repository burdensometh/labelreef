package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func lockState(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".daemon.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("state directory already owned by a daemon: %s", dir)
		}
		return nil, fmt.Errorf("lock state directory %s: %w", dir, err)
	}
	return func() { f.Close() }, nil
}
