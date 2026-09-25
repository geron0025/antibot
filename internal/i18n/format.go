package i18n

import (
	"strconv"
	"strings"
	"time"
)

// locale is how a language writes numbers and dates.
type locale struct {
	group   string // between groups of thousands
	decimal string
	percent string // between a number and the percent sign
	time    string // an event: day and month, no year
	short   string // a point on an axis: an event without the seconds
	date    string // a term: with the year
}

// US formats for English: months first. The time of day is 24-hour in
// both.
var locales = map[Lang]locale{
	EN: {group: ",", decimal: ".", percent: "", time: "01/02 15:04:05", short: "01/02 15:04", date: "01/02/2006"},
	RU: {group: " ", decimal: ",", percent: " ", time: "02.01 15:04:05", short: "02.01 15:04", date: "02.01.2006"},
}

func (p *Printer) locale() locale {
	if l, ok := locales[p.lang]; ok {
		return l
	}
	return locales[EN]
}

// Number prints an integer with the language's digit grouping.
func (p *Printer) Number(n int64) string {
	s := strconv.FormatInt(n, 10)
	sign := ""
	if n < 0 {
		sign, s = "-", s[1:]
	}
	group := p.locale().group
	var b strings.Builder
	for i, digit := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(group)
		}
		b.WriteRune(digit)
	}
	return sign + b.String()
}

// Decimal prints a fraction with the given number of digits after the
// language's decimal separator.
func (p *Printer) Decimal(f float64, digits int) string {
	return strings.Replace(strconv.FormatFloat(f, 'f', digits, 64), ".", p.locale().decimal, 1)
}

// Percent prints part of whole as a percentage with one decimal digit.
// A zero whole is 0%.
func (p *Printer) Percent(part, whole int) string {
	value := "0"
	if whole != 0 {
		value = p.Decimal(100*float64(part)/float64(whole), 1)
	}
	return value + p.locale().percent + "%"
}

// Time prints the moment of an event: day, month and time of day, 24-hour
// in every language — it is a log, and AM and PM get in the way there.
// The zero time is a dash.
func (p *Printer) Time(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format(p.locale().time)
}

// Short prints a moment without the seconds and the year: a point on a
// chart's axis that spans days.
func (p *Printer) Short(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format(p.locale().short)
}

// Date prints a date with the year: for terms that run into other years.
// The zero time is a dash.
func (p *Printer) Date(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format(p.locale().date)
}
