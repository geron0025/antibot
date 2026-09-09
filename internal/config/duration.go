package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is time in human form: 30s, 15m, 24h.
//
// A dedicated type is needed because yaml.v3 knows nothing about
// time.Duration and would parse "30s" as an error and "30" as thirty
// nanoseconds. The second is worse than the first: a check interval of
// thirty nanoseconds does not break parsing, it just burns the CPU in
// production.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("a duration must be a string like 30s or 15m")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%q is not a duration: %w", s, err)
	}
	if v < 0 {
		return fmt.Errorf("%q is a negative duration", s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}
