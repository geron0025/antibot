package proposals

import (
	"os"
	"path/filepath"
	"testing"
)

// The copy embedded into the binary is the copy that ships: a node
// running on somebody else's machine has no docs/ directory to fall
// back to, and a drifted embedded copy would validate a shape the
// protocol no longer promises.
func TestEmbeddedSchemasMatchDocs(t *testing.T) {
	for _, name := range []string{"proposals.schema.json", "proposal-feedback.schema.json"} {
		embedded, err := schemaFS.ReadFile("schema/" + name)
		if err != nil {
			t.Fatalf("%s: embedded copy: %v", name, err)
		}
		onDisk, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", name))
		if err != nil {
			t.Fatalf("%s: docs/schema copy: %v", name, err)
		}
		if string(embedded) != string(onDisk) {
			t.Errorf("%s: the embedded copy differs from docs/schema, byte for byte", name)
		}
	}
}
