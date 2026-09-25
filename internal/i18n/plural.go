package i18n

// pluralForms are the forms each language needs for an integer count,
// named as in CLDR. Only integers: nothing on the pages counts halves.
var pluralForms = map[Lang][]string{
	EN: {"one", "other"},
	RU: {"one", "few", "many"},
}

// pluralForm is the CLDR form of the integer n in the language.
func pluralForm(l Lang, n int) string {
	if n < 0 {
		n = -n
	}
	switch l {
	case RU:
		switch mod10, mod100 := n%10, n%100; {
		case mod10 == 1 && mod100 != 11:
			return "one"
		case mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14):
			return "few"
		default:
			return "many"
		}
	default:
		if n == 1 {
			return "one"
		}
		return "other"
	}
}
