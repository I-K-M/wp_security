package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateExclusiveReport(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	if err := save(p, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	if err := save(p, []byte("overwrite")); err == nil {
		t.Fatal("overwrite allowed")
	}
}
func TestReportRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report")
	os.Symlink(filepath.Join(dir, "secret"), p)
	if err := save(p, []byte("{}")); err == nil {
		t.Fatal("symlink accepted")
	}
}
