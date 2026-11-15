package authz

import (
	"os"
	"strings"
	"testing"
)

// The RBAC matrix in docs must match the catalog. Regenerate with:
//   scripts/go.sh run ./cmd/pathosctl rbac-matrix
func TestRBACMatrixDocIsCurrent(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/RBAC_MATRIX.md")
	if os.IsNotExist(err) {
		t.Skip("docs not available in this build context")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), MarkdownMatrix()) {
		t.Fatal("docs/RBAC_MATRIX.md is out of date; regenerate the table with `pathosctl rbac-matrix`")
	}
}
