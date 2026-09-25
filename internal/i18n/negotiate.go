package i18n

import (
	"strconv"
	"strings"
)

// Match picks a supported language from an Accept-Language header,
// honouring the q weights and taking a region as its language: ru-RU is
// ru. Nothing supported, or a header that does not parse, is fallback.
func Match(header string, fallback Lang) Lang {
	best, bestQ := fallback, 0.0
	for _, part := range strings.Split(header, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if name, value, ok := strings.Cut(strings.TrimSpace(params), "="); ok && strings.TrimSpace(name) == "q" {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				continue
			}
			q = parsed
		}
		primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
		lang, ok := Parse(primary)
		// Equal weights keep the first: the browser lists in the order
		// the human prefers.
		if ok && q > bestQ {
			best, bestQ = lang, q
		}
	}
	return best
}
