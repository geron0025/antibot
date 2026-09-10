package admin

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/geron0025/antibot/internal/summary"
)

// The charts are drawn on the server as SVG. Not for want of a library:
// the CSP forbids inline styles and there is no JavaScript here at all,
// while SVG geometry lives in attributes, which the CSP does not touch.
// A bar sized by style="height: …" is silently dropped by the browser —
// which is exactly how the first version of this page drew an empty box.

// answerLabels name the answer classes for a human.
var answerLabels = [summary.AnswerCount]string{
	"2xx from the site",
	"3xx from the site",
	"4xx from the site",
	"5xx from the site",
	"not let through by the node",
	"no status recorded",
}

// answerClass is the CSS class that gives an answer class its colour. The
// colour follows the class, never its rank: 5xx is the same red in the
// ring, in the columns and in the legend.
func answerClass(a summary.Answer) string { return "a-" + a.String() }

// legendRow is one answer class with its numbers.
type legendRow struct {
	Name  string // the filter value: "2xx", "blocked"
	Label string
	Class string
	Count int
	Share string
}

// legend lists every class, empty ones included: "5xx: 0" is news too.
// Only "no status" is left out when empty — it exists for old events.
func legend(answers [summary.AnswerCount]int) []legendRow {
	total := 0
	for _, n := range answers {
		total += n
	}
	var rows []legendRow
	for a := summary.Answer(0); a < summary.AnswerCount; a++ {
		if a == summary.AnswerNone && answers[a] == 0 {
			continue
		}
		rows = append(rows, legendRow{
			Name: a.String(), Label: answerLabels[a], Class: answerClass(a),
			Count: answers[a], Share: share(answers[a], total),
		})
	}
	return rows
}

// --- the ring of answers ---

type donutSegment struct {
	Class  string
	Title  string
	Dash   string // stroke-dasharray
	Offset string // stroke-dashoffset
}

type donutChart struct {
	Total    int
	Segments []donutSegment
	Legend   []legendRow
}

// donutGap is the surface gap between neighbouring arcs, in hundredths
// of the circle.
const donutGap = 0.6

// newDonut lays the answers out along a circle whose radius makes its
// circumference exactly 100: an arc's length is then its share in
// percent, and a stroke-dasharray is all the geometry there is.
func newDonut(answers [summary.AnswerCount]int) donutChart {
	d := donutChart{Legend: legend(answers)}
	present := 0
	for _, n := range answers {
		d.Total += n
		if n > 0 {
			present++
		}
	}
	if d.Total == 0 {
		return d
	}
	gap := 0.0
	if present > 1 {
		gap = donutGap
	}

	offset := 0.0
	for a := summary.Answer(0); a < summary.AnswerCount; a++ {
		n := answers[a]
		if n == 0 {
			continue
		}
		pct := 100 * float64(n) / float64(d.Total)
		// A sliver still has to be seen: one 5xx among ten thousand
		// answers is exactly the one worth noticing.
		arc := math.Max(pct-gap, 0.4)
		d.Segments = append(d.Segments, donutSegment{
			Class:  answerClass(a),
			Title:  fmt.Sprintf("%s: %s (%s)", answerLabels[a], thousands(n), share(n, d.Total)),
			Dash:   fmt.Sprintf("%.3f %.3f", arc, 100-arc),
			Offset: fmt.Sprintf("%.3f", -offset),
		})
		offset += pct
	}
	return d
}

// --- requests over time ---

type columnSegment struct {
	Class string
	D     string
}

type column struct {
	HitX, HitW string
	Title      string
	Segments   []columnSegment
}

type gridLine struct {
	Y     string
	Label string
}

type axisLabel struct {
	X    string
	Text string
}

type seriesRow struct {
	Time   string
	Counts []int
	Total  int
}

type columnsChart struct {
	Width, Height int
	Left, Right   string
	Top, Base     string
	LabelY        string

	Grid    []gridLine
	Columns []column
	XLabels []axisLabel
	Legend  []legendRow

	// The table view of the same numbers: a tooltip enhances, it must not
	// be the only way to read a value.
	Classes []string
	Rows    []seriesRow
}

// The chart's coordinate system. The SVG scales as a whole, and its card
// is about 750 pixels wide on a desktop screen, so these are close to
// pixels there: a wider box would shrink the axis labels to nothing.
const (
	chartWidth   = 800
	chartHeight  = 206
	plotLeft     = 52.0
	plotRight    = 794.0
	plotTop      = 10.0
	plotBase     = 180.0
	columnMax    = 24.0 // a column never fills its slot: the rest is air
	columnGap    = 2.0  // the surface gap between stacked segments
	columnRadius = 4.0
)

// newColumns stacks each time bucket by answer class. It returns nil when
// there is nothing to draw.
func newColumns(points []summary.Point, period time.Duration) *columnsChart {
	var totals [summary.AnswerCount]int
	largest := 0
	for _, p := range points {
		for a, n := range p.Answers {
			totals[a] += n
		}
		if p.Events > largest {
			largest = p.Events
		}
	}
	if largest == 0 {
		return nil
	}

	step := niceStep(largest, 4)
	top := ((largest + step - 1) / step) * step
	height := plotBase - plotTop
	scale := height / float64(top)

	c := &columnsChart{
		Width: chartWidth, Height: chartHeight,
		Left: coord(plotLeft), Right: coord(plotRight),
		Top: coord(plotTop), Base: coord(plotBase),
		LabelY: coord(plotBase + 18),
	}
	for a := summary.Answer(0); a < summary.AnswerCount; a++ {
		if totals[a] > 0 {
			c.Legend = append(c.Legend, legendRow{
				Name: a.String(), Label: answerLabels[a], Class: answerClass(a),
			})
			c.Classes = append(c.Classes, a.String())
		}
	}
	for v := 0; v <= top; v += step {
		c.Grid = append(c.Grid, gridLine{
			Y: coord(plotBase - float64(v)*scale), Label: thousands(v),
		})
	}

	width := period / time.Duration(len(points))
	if len(points) > 1 {
		width = points[1].Time.Sub(points[0].Time)
	}
	format := "15:04"
	if period > 24*time.Hour {
		format = "02.01 15:04"
	}

	slot := (plotRight - plotLeft) / float64(len(points))
	w := math.Min(columnMax, slot*0.72)
	every := (len(points) + 5) / 6

	for i, p := range points {
		x := plotLeft + float64(i)*slot + (slot-w)/2
		col := column{HitX: coord(plotLeft + float64(i)*slot), HitW: coord(slot)}

		from := p.Time.Local()
		title := fmt.Sprintf("%s–%s · %s requests", from.Format(format),
			from.Add(width).Format("15:04"), thousands(p.Events))
		row := seriesRow{Time: from.Format(format), Total: p.Events}

		var present []summary.Answer
		for a := summary.Answer(0); a < summary.AnswerCount; a++ {
			if totals[a] > 0 {
				row.Counts = append(row.Counts, p.Answers[a])
			}
			if p.Answers[a] > 0 {
				present = append(present, a)
				title += fmt.Sprintf("\n%s: %s", answerLabels[a], thousands(p.Answers[a]))
			}
		}

		cursor := plotBase
		for k, a := range present {
			h := math.Max(float64(p.Answers[a])*scale, 1)
			last := k == len(present)-1
			y := cursor - h
			if !last && h > 2*columnGap {
				// The gap is taken from the top of the lower segment, so
				// the stack stays exactly as tall as its total.
				y += columnGap
			}
			var d string
			if last {
				d = roundedTop(x, y, w, cursor-y)
			} else {
				d = rect(x, y, w, cursor-y)
			}
			col.Segments = append(col.Segments, columnSegment{Class: answerClass(a), D: d})
			cursor -= h
		}
		col.Title = title
		c.Columns = append(c.Columns, col)
		c.Rows = append(c.Rows, row)

		if i%every == 0 {
			c.XLabels = append(c.XLabels, axisLabel{X: coord(x + w/2), Text: from.Format(format)})
		}
	}
	return c
}

// niceStep picks a tick step of 1, 2 or 5 times a power of ten, so that
// the axis reads 0, 500, 1,000 rather than 0, 437, 874.
func niceStep(largest, ticks int) int {
	rough := float64(largest) / float64(ticks)
	if rough <= 1 {
		return 1
	}
	magnitude := math.Pow(10, math.Floor(math.Log10(rough)))
	for _, m := range []float64{1, 2, 5, 10} {
		if m*magnitude >= rough {
			return int(m * magnitude)
		}
	}
	return int(10 * magnitude)
}

func rect(x, y, w, h float64) string {
	return fmt.Sprintf("M%s %sH%sV%sH%sZ",
		coord(x), coord(y+h), coord(x+w), coord(y), coord(x))
}

// roundedTop is a column end: rounded at the data end, square at the
// baseline.
func roundedTop(x, y, w, h float64) string {
	r := math.Min(columnRadius, math.Min(w/2, h))
	return fmt.Sprintf("M%s %sV%sQ%s %s %s %sH%sQ%s %s %s %sV%sZ",
		coord(x), coord(y+h),
		coord(y+r),
		coord(x), coord(y), coord(x+r), coord(y),
		coord(x+w-r),
		coord(x+w), coord(y), coord(x+w), coord(y+r),
		coord(y+h))
}

func coord(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

// bucketsFor splits a period into intervals a human counts in: minutes
// for an hour, half-hours for a day, three hours for a week.
func bucketsFor(period time.Duration) int {
	switch {
	case period <= time.Hour:
		return 60
	case period <= 24*time.Hour:
		return 48
	case period <= 7*24*time.Hour:
		return 56
	default:
		return 60
	}
}

// --- numbers for a human ---

// thousands prints 1234567 as 1,234,567.
func thousands(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return neg + s
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, exp := float64(n)/unit, 0
	for value >= unit && exp < 4 {
		value /= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", value, "KMGTP"[exp])
}

func formatLatency(d time.Duration) string {
	switch {
	case d <= 0:
		return "—"
	case d < time.Millisecond:
		return "<1 ms"
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
}
