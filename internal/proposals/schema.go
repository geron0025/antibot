package proposals

import (
	"embed"

	"github.com/geron0025/antibot/internal/schemacheck"
)

// schemaFS carries a copy of the two schemas this package validates
// against, so that a node running on somebody else's machine — with no
// docs/ directory anywhere near it — can still check a proposals
// document before a single line reaches the owner's screen.
//
// schema_equal_test.go holds this copy to the one in docs/schema byte
// for byte: the embedded copy is what ships, and a drifted one would
// validate a shape the protocol no longer promises.
//
//go:embed schema/proposals.schema.json schema/proposal-feedback.schema.json
var schemaFS embed.FS

var (
	proposalsSchema        map[string]any
	proposalFeedbackSchema map[string]any
)

func init() {
	proposalsSchema = mustLoad("schema/proposals.schema.json")
	proposalFeedbackSchema = mustLoad("schema/proposal-feedback.schema.json")
}

func mustLoad(path string) map[string]any {
	raw, err := schemaFS.ReadFile(path)
	if err != nil {
		panic(err)
	}
	s, err := schemacheck.LoadBytes(raw)
	if err != nil {
		panic(err)
	}
	return s
}
