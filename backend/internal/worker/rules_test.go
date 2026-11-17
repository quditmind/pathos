package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCustomRules(t *testing.T) {
	dir, err := writeCustomRules([]byte(`{"custom_rules":[{"name":"../../etc/passwd","content":"rules: []"}]}`))
	if err != nil || dir == "" {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 1 || filepath.Base(files[0]) != "custom-000.yml" {
		t.Errorf("file names are generated, never taken from the server: %v", files)
	}
	if d, err := writeCustomRules([]byte(`{}`)); d != "" || err != nil {
		t.Errorf("no rules: %q %v", d, err)
	}
}
