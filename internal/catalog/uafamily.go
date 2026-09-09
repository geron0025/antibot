package catalog

import "strings"

// The families a User-Agent string is classified into. The same names
// the fact set uses for fingerprints and the aggregate uses for
// ua_family, so that the two can be compared at all.
const (
	FamilyChrome  = "chrome"
	FamilyFirefox = "firefox"
	FamilySafari  = "safari"
	FamilyCurl    = "curl"
	FamilyPython  = "python"
	FamilyGo      = "go"
	FamilyBot     = "bot"
	FamilyUnknown = "unknown"
)

// crawlers are the names clients call themselves by. Recognizing one
// means exactly one thing here: **do not compare** its claim against the
// TLS fingerprint. Whether the claim is true needs verified networks,
// which this string cannot provide.
var crawlers = []string{
	"googlebot", "bingbot", "yandexbot", "applebot", "petalbot",
	"duckduckbot", "baiduspider", "ahrefsbot", "semrushbot", "mj12bot",
	"dotbot", "bytespider", "gptbot", "claudebot", "ccbot", "perplexitybot",
	"facebookexternalhit", "twitterbot", "telegrambot", "slackbot",
	"bot/", "crawler", "spider",
}

// UAFamily classifies a User-Agent string.
//
// The order of the checks is the whole content of this function.
// A crawler is recognized first: its string almost always carries
// "Chrome" and "Safari" too, and reading it as a browser would turn
// every search engine into a liar. Then the tools, which name
// themselves plainly. Then the browsers, from the most specific
// marker to the least: every Chromium browser says "Safari", and
// Safari itself is what is left when nothing else matched.
func UAFamily(ua string) string {
	if ua == "" {
		return FamilyUnknown
	}
	s := strings.ToLower(ua)

	for _, name := range crawlers {
		if strings.Contains(s, name) {
			return FamilyBot
		}
	}

	switch {
	case strings.HasPrefix(s, "curl/"):
		return FamilyCurl
	case strings.Contains(s, "python-requests") || strings.Contains(s, "python-urllib") ||
		strings.Contains(s, "aiohttp") || strings.Contains(s, "httpx"):
		return FamilyPython
	case strings.Contains(s, "go-http-client"):
		return FamilyGo
	}

	switch {
	case strings.Contains(s, "firefox/") || strings.Contains(s, "fxios/"):
		return FamilyFirefox
	// Edge, Opera, Yandex Browser and the rest of Chromium: the engine
	// is Chrome's, and so is the handshake. Calling them a mismatch
	// would accuse the second most popular browser on earth.
	case strings.Contains(s, "edg/") || strings.Contains(s, "edga/") ||
		strings.Contains(s, "opr/") || strings.Contains(s, "yabrowser/") ||
		strings.Contains(s, "chrome/") || strings.Contains(s, "crios/"):
		return FamilyChrome
	case strings.Contains(s, "safari/") && strings.Contains(s, "version/"):
		return FamilySafari
	}

	return FamilyUnknown
}
