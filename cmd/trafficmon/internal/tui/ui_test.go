package tui

import (
	"context"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/dns"
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

// destinationRows is the ungrouped fixture, including a bracketed IPv6
// remote address that is long enough to exercise the label column.
func destinationRows() []aggregate.Row {
	return []aggregate.Row{
		{
			Key: "412|192.168.1.10|51000|140.82.112.3|443|tcp", Label: "com.apple.WebKit.Networking", PID: 412,
			LocalAddr: "192.168.1.10", LocalPort: 51000,
			RemoteAddr: "140.82.112.3", RemotePort: 443, Proto: "tcp", State: "ESTABLISHED",
			RateInBps: 2202009, RateOutBps: 184320,
			BytesInTotal: 134217728, BytesOutTotal: 12582912,
			Connections: 1, LastSeen: testNow,
		},
		{
			Key: "22|192.168.1.10|51001|2606:4700:4700::1111|53|udp", Label: "sshd", PID: 22,
			LocalAddr: "192.168.1.10", LocalPort: 51001,
			RemoteAddr: "2606:4700:4700::1111", RemotePort: 53, Proto: "udp",
			RateInBps: 900, BytesInTotal: 90000,
			Connections: 1, LastSeen: testNow,
		},
	}
}

// stubHostname is a hostname source for the layout tests, which care that the
// column is there and how wide it is rather than what is in it.
func stubHostname(r aggregate.Row) string { return r.RemoteAddr }

// newTestModel builds a model with a fixed viewport and pre-loaded rows,
// bypassing the aggregator so the view can be exercised without a capture. Its
// resolver never resolves anything, which is the state every destination
// starts in: the bare address, shown until a name arrives.
func newTestModel(rows []aggregate.Row, width, height int) Model {
	m := NewModel(context.Background(), nil, nil, nil, "en0")
	m.rows = rows
	m.now = testNow
	m.width, m.height = width, height
	return m
}

// newResolvedModel builds a destination-mode model over destinationRows whose
// resolver has already answered for every address in names, so the view can be
// asserted on with hostnames actually on screen.
//
// The lookups are asynchronous by design, so the helper drives them the way the
// render loop does — by asking repeatedly — rather than reaching into the
// resolver. Nothing here touches the network: the resolver is built over a
// function that answers from names alone.
func newResolvedModel(t *testing.T, names map[string]string, width, height int) Model {
	t.Helper()

	m := newTestModel(destinationRows(), width, height)
	m.grouping = aggregate.GroupNone
	m.resolver = dns.NewResolverWith(func(_ context.Context, addr string) ([]string, error) {
		if name, ok := names[addr]; ok {
			return []string{name + "."}, nil
		}
		return nil, errors.New("no such host")
	})

	waitFor(t, "every destination to resolve", func() bool {
		for _, r := range m.rows {
			if want, ok := names[r.RemoteAddr]; ok && m.resolveHostname(r) != want {
				return false
			}
		}
		return true
	})
	return m
}

// waitFor polls cond until it holds, failing the test if it never does. It is
// how the tests over background work stay deterministic without a fixed sleep:
// the poll ends the moment the work lands, and the deadline is long enough
// that only a genuine failure reaches it.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	if cond() {
		return
	}

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-ticker.C:
			if cond() {
				return
			}
		case <-timeout.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// testSnapshot is the aggregator output the interaction tests drive the model
// from. Two of its three processes talk to the same host on different ports,
// so that by-process, by-destination-by-ip and by-destination-by-ip:port each
// roll the same data up into a different number of rows.
func testSnapshot() aggregate.Snapshot {
	return aggregate.Snapshot{
		At: testNow,
		Connections: []aggregate.ConnectionRecord{
			{
				PID: 412, ProcessName: "com.apple.WebKit.Networking",
				LocalPort: 51000, RemoteAddr: "140.82.112.3", RemotePort: 443, Proto: "tcp",
				BytesInTotal: 134217728, BytesOutTotal: 12582912,
				RateInBps: 2202009, RateOutBps: 184320, LastSeen: testNow,
			},
			{
				PID: 980, ProcessName: "Google Chrome Helper",
				LocalPort: 51001, RemoteAddr: "140.82.112.3", RemotePort: 80, Proto: "tcp",
				BytesInTotal: 4194304, BytesOutTotal: 786432,
				RateInBps: 51200, RateOutBps: 8192, LastSeen: testNow,
			},
			{
				PID: 22, ProcessName: "sshd",
				LocalPort: 22, RemoteAddr: "10.0.0.5", RemotePort: 51234, Proto: "tcp",
				BytesInTotal: 1048576, BytesOutTotal: 2097152,
				RateInBps: 1024, RateOutBps: 1536, LastSeen: testNow,
			},
		},
	}
}

// newLiveModel builds a model holding testSnapshot with its rows already
// derived from it: the state the model sits in between ticks, which is what
// every keypress acts on.
func newLiveModel() Model {
	m := newTestModel(nil, 100, 12)
	m.snap = testSnapshot()
	m.rebuild()
	return m
}

// keyRows builds a row set carrying nothing but identity, for the tests about
// where the cursor lands rather than what a row says.
func keyRows(keys ...string) []aggregate.Row {
	rows := make([]aggregate.Row, len(keys))
	for i, k := range keys {
		rows[i] = aggregate.Row{Key: k, Label: k}
	}
	return rows
}

// specialKeys maps the names the bindings are declared with to the key types
// bubbletea reports them as, so a test can drive Update with the same strings
// keys.go spells out.
var specialKeys = map[string]tea.KeyType{
	"up":        tea.KeyUp,
	"down":      tea.KeyDown,
	"pgup":      tea.KeyPgUp,
	"pgdown":    tea.KeyPgDown,
	"home":      tea.KeyHome,
	"end":       tea.KeyEnd,
	"tab":       tea.KeyTab,
	"enter":     tea.KeyEnter,
	"esc":       tea.KeyEsc,
	"backspace": tea.KeyBackspace,
	"ctrl+c":    tea.KeyCtrlC,
	"ctrl+b":    tea.KeyCtrlB,
	"ctrl+f":    tea.KeyCtrlF,
}

// keyMsg builds the message bubbletea would deliver for a named key. Anything
// not in specialKeys is a literal rune, which is how every printable binding
// arrives.
func keyMsg(name string) tea.KeyMsg {
	if t, ok := specialKeys[name]; ok {
		return tea.KeyMsg(tea.Key{Type: t})
	}
	return tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune(name)})
}

// press drives one keypress through Update, which is all a test needs to
// exercise the input path: no terminal, no program loop.
func press(t *testing.T, m Model, name string) (Model, tea.Cmd) {
	t.Helper()

	// A helper that built the wrong message would silently test nothing, so
	// check it round-trips to the name the binding is declared with.
	if got := keyMsg(name).String(); got != name {
		t.Fatalf("keyMsg(%q) is delivered as %q", name, got)
	}

	next, cmd := m.Update(keyMsg(name))
	return next.(Model), cmd
}

// pressAll drives a sequence of keypresses through Update.
func pressAll(t *testing.T, m Model, names ...string) Model {
	t.Helper()
	for _, name := range names {
		m, _ = press(t, m, name)
	}
	return m
}

// allBindings returns every binding declared on a KeyMap. Walking the struct
// rather than a hand-written list is what makes the tests over it notice a
// binding that was added but never documented or wired up.
func allBindings(t *testing.T, k KeyMap) []key.Binding {
	t.Helper()

	v := reflect.ValueOf(k)
	out := make([]key.Binding, 0, v.NumField())
	for i := range v.NumField() {
		b, ok := v.Field(i).Interface().(key.Binding)
		if !ok {
			t.Fatalf("KeyMap field %s is not a key.Binding", v.Type().Field(i).Name)
		}
		out = append(out, b)
	}
	return out
}
