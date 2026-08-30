package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/boyvinall/mac-nethogs/aggregate"
)

// TestMain pins the colour profile so the rendered strings the tests assert on
// do not depend on the TERM the suite happens to run under. Ascii is the
// default because it strips every escape sequence, leaving the plain text that
// layout assertions care about; the tests that are specifically about styling
// opt into ANSI with withANSI.
func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	os.Exit(m.Run())
}

// withANSI turns escape sequences back on for one test, so that styles which
// are attributes rather than colours — faint, reverse — actually reach the
// output and can be asserted on.
func withANSI(t *testing.T) {
	t.Helper()
	lipgloss.SetColorProfile(termenv.ANSI)
	t.Cleanup(func() { lipgloss.SetColorProfile(termenv.Ascii) })
}

// ansiPattern matches the SGR sequences lipgloss emits.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stripANSI returns the plain text of a styled string.
func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }

// trimRight removes trailing padding from every line. Goldens are compared
// this way so that the expected strings in the test source do not carry
// invisible trailing whitespace that an editor would silently eat; the exact
// padded width is asserted separately, by the alignment tests.
func trimRight(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

// testNow is a fixed clock, so "closed" is a property of the fixtures rather
// than of how long the suite took to run.
var testNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// processRows is the by-process fixture: a spread of magnitudes from a single
// byte to hundreds of megabytes, a long label that has to truncate, and one
// row (launchd) idle for longer than aggregate.IdleThreshold so it renders
// closed.
func processRows() []aggregate.Row {
	return []aggregate.Row{
		{
			Key: "412", Label: "com.apple.WebKit.Networking", PID: 412,
			RateInBps: 2202009, RateOutBps: 184320,
			BytesInTotal: 134217728, BytesOutTotal: 12582912,
			Connections: 14, LastSeen: testNow,
		},
		{
			Key: "980", Label: "Google Chrome Helper", PID: 980,
			RateInBps: 51200, RateOutBps: 8192,
			BytesInTotal: 4194304, BytesOutTotal: 786432,
			Connections: 6, LastSeen: testNow,
		},
		{
			Key: "1", Label: "launchd", PID: 1,
			BytesInTotal: 1023, BytesOutTotal: 512,
			Connections: 1, LastSeen: testNow.Add(-9 * time.Second),
		},
		{
			Key: "22", Label: "sshd", PID: 22,
			RateInBps: 1024, RateOutBps: 1536,
			BytesInTotal: 1048576, BytesOutTotal: 2097152,
			Connections: 2, LastSeen: testNow,
		},
		{
			Key: "-1", Label: "unknown", PID: -1,
			RateInBps:    12,
			BytesInTotal: 4096,
			Connections:  3, LastSeen: testNow.Add(-time.Second),
		},
	}
}

// destinationRows is the by-destination fixture, including a bracketed IPv6
// address that is long enough to exercise the label column.
func destinationRows() []aggregate.Row {
	return []aggregate.Row{
		{
			Key: "140.82.112.3:443", Label: "140.82.112.3:443",
			RemoteAddr: "140.82.112.3", RemotePort: 443,
			RateInBps: 2202009, RateOutBps: 184320,
			BytesInTotal: 134217728, BytesOutTotal: 12582912,
			Connections: 4, LastSeen: testNow,
		},
		{
			Key: "[2606:4700:4700::1111]:53", Label: "[2606:4700:4700::1111]:53",
			RemoteAddr: "2606:4700:4700::1111", RemotePort: 53,
			RateInBps: 900, BytesInTotal: 90000,
			Connections: 1, LastSeen: testNow,
		},
	}
}

// newTestModel builds a model with a fixed viewport and pre-loaded rows,
// bypassing the aggregator so the view can be exercised without a capture.
func newTestModel(rows []aggregate.Row, width, height int) Model {
	m := NewModel(nil, "en0")
	m.rows = rows
	m.now = testNow
	m.width, m.height = width, height
	return m
}
