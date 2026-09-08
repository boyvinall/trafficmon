// Package tui implements the Bubble Tea front end.
package tui

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/boyvinall/trafficmon/aggregate"
	"github.com/boyvinall/trafficmon/dns"
	"github.com/boyvinall/trafficmon/dpi"
)

// TickInterval is the render cadence. It is deliberately independent of both
// the capture rate and the process poll rate.
const TickInterval = time.Second

// appName is the title shown at the left of the header bar.
const appName = "trafficmon"

// connChromeLines and eventsChromeLines are how many lines View spends on
// furniture rather than data in each panel: the panel's top and bottom
// border, its column-title line, and — for Connections only — the header
// line above it (Events has no breadcrumb header of its own). The footer
// below both panels is accounted for separately, once per View, since it is
// shared rather than belonging to either panel.
const (
	connChromeLines   = 4
	eventsChromeLines = 3
)

// panelTitle and eventsPanelTitle are the two panels' border-inlaid titles.
const (
	panelTitle       = "Connections"
	eventsPanelTitle = "Events"
)

// eventsHeightFraction is the default share of the two-panel area the events
// panel takes on the first WindowSizeMsg: one part in four, connections
// taking the rest.
const eventsHeightFraction = 4

// minPanelDataRows is the fewest data rows either panel is ever left with,
// whether from the default split or from dragging the divider: enough that a
// panel squeezed all the way down still shows something.
const minPanelDataRows = 3

// defaultPageSize is how far PgUp/PgDn move the cursor before the terminal
// height is known and a real screenful can be measured.
const defaultPageSize = 10

// emptyMessage stands in for the table body before any traffic has been seen,
// so a working but idle capture does not look like a broken one.
const emptyMessage = "  (no traffic yet)"

// emptyFilterMessage stands in for the table body of a view whose filter
// matches nothing. It takes precedence over emptyMessage: a filter is
// something the user typed a moment ago and can undo, so it is far and away
// the likeliest explanation for an empty table, and "no traffic yet" would be
// a flat contradiction of the header bar naming the filter that emptied it.
const emptyFilterMessage = "  (nothing matches the filter — / to change it)"

// filterPrompt marks the filter input, echoing the key that opened it the way
// less and vim do, so the line reads as the thing `/` just started.
const filterPrompt = "/"

// filterHint spells out the two keys that close the input, and the one thing
// about it that is not guessable: that committing nothing is how a filter is
// taken off again.
const filterHint = "enter apply · empty clears · esc cancel"

// maxFilterLabel bounds the filter shown in the header bar. The filter is the
// one piece of the status the user types, so it is the one piece that could
// otherwise be long enough to shove everything else off the line.
const maxFilterLabel = 16

type tickMsg time.Time

// panelFocus is which of the two panels — Connections or Events — currently
// has the keyboard, cycled with FocusNext (tab). focusConnections is the
// zero value, which is what NewModel starts with.
type panelFocus uint8

const (
	focusConnections panelFocus = iota
	focusEvents
)

// Model is the root Bubble Tea model.
//
// Its methods follow one rule for receivers: a pointer receiver mutates the
// local copy Update is holding (moveCursor, refresh, setSort, and the rest of
// that family), while a value receiver only ever reads it (View,
// resolveHostname, and everything Bubble Tea itself calls). Neither kind
// needs to return a changed Model — Update passes its own copy by pointer to
// every mutator it calls, then returns that same copy.
type Model struct {
	agg *aggregate.Aggregator
	// resolver turns remote addresses into hostnames. It answers from cache
	// and never blocks, so View may call it freely; see dns.Resolver.
	resolver *dns.Resolver
	// hostnameCache is the per-IP fallback DPI populates: a connection with no
	// SNI of its own can borrow the most recent hostname found for the same
	// remote IP. May be nil, in which case that fallback step is skipped.
	hostnameCache *dpi.HostnameCache
	// ctx is the program's lifetime, held so that the background lookups the
	// render loop starts are wound up with it. Bubble Tea hands Update and
	// View no context of their own, and the alternative — resolving against
	// context.Background — would leave Lookup's cancellation permanently
	// theoretical.
	ctx context.Context

	// interfaces is every interface capture was told about at startup, in the
	// order the picker lists them. activeInterfaces says which of them are
	// currently shown, all true until `i` narrows them — a display filter
	// over rows capture already produced, never a capture restart.
	interfaces       []string
	activeInterfaces map[string]bool
	// showIfacePicker and ifaceCursor are the interface picker's own state,
	// the same shape showHelp/cursor take for the help overlay and table.
	showIfacePicker bool
	ifaceCursor     int

	keys   KeyMap
	styles Styles
	// help renders both the footer hint line and the `?` overlay from keys,
	// so the two can never drift apart from the bindings Update acts on.
	help help.Model

	// grouping controls how connections roll up into rows, cycled with `g`.
	// The zero value, aggregate.GroupNone, is what NewModel starts with:
	// one row per open connection.
	grouping aggregate.Grouping
	// sort is the column driving row order, cycled with `s`. NewModel starts
	// it on SortPID rather than the zero value SortRate: which process is
	// which stays put from one refresh to the next, unlike rate or total,
	// so the table doesn't reshuffle itself the moment traffic starts.
	sort SortKey

	// snap is the most recent aggregator snapshot, kept so that a change of
	// mode, grouping, sort or filter can rebuild the table from it on the very
	// next frame. Waiting for the next tick would leave the header describing
	// one view while the table still showed another, and while paused it would
	// never take effect at all.
	snap aggregate.Snapshot

	rows   []aggregate.Row
	cursor int
	// now is the timestamp of the most recent refresh. The view needs it to
	// decide which rows have gone quiet and should render dimmed; holding it
	// on the model rather than calling time.Now inside View keeps rendering a
	// pure function of the model, which is what makes it testable.
	now      time.Time
	paused   bool
	showHelp bool

	// filter is the substring the table is narrowed to, and input is the line
	// editor `/` opens to change it. The two are kept apart because the filter
	// outlives the input: it goes on narrowing the table long after the input
	// has been dismissed, and it is what the header reports.
	filter string
	input  textinput.Model
	// filtering says the input has the keyboard, which is what stops the
	// single-letter navigation bindings from firing on every character typed.
	filtering bool
	// filterBefore is the filter the input was opened over, so esc can put it
	// back. The table filters as the user types, so without it a cancelled
	// edit would leave the previous filter as thoroughly gone as a committed
	// one.
	filterBefore string

	// showListening says whether rows for TCP sockets in the LISTEN state are
	// shown. It starts true — every socket enumeration already reported them,
	// so hiding them is an opt-in narrowing, not the default — and `l` flips
	// it. Only the ungrouped view ever sets Row.State (see aggregate.Row's
	// grouped constructors), so a grouped view is unaffected either way.
	showListening bool
	// showTCP and showUDP say whether rows for each transport protocol are
	// shown, toggled independently by `t` and `u`. Both start true for the
	// same reason showListening does, and are just as much a no-op on a
	// grouped view: only the ungrouped view ever sets Row.Proto.
	showTCP, showUDP bool
	// showIPv4 and showIPv6 say whether rows whose remote address is of each
	// family are shown, toggled independently by `4` and `6`. Both start
	// true for the same reason showListening does; a row whose remote
	// address does not parse as an IP at all is unaffected by either, the
	// same "unclassified rows are never hidden" rule showTCP/showUDP follow.
	showIPv4, showIPv6 bool
	// showPrivate says whether rows whose remote address is RFC1918/RFC4193
	// private are shown, toggled by `P`. It starts true for the same reason
	// showListening does, and is a no-op on a row whose remote address does
	// not parse.
	showPrivate bool

	// events is the events panel's own bounded history, appended to at the
	// end of every refresh — see appendEvents. Snapshot itself drops its five
	// event streams on the very next Refresh, so this ring is the only place
	// they are retained across ticks.
	events eventRing
	// eventsCursor is the events panel's own scroll position, independent of
	// the connections table's cursor: the two panels are scrolled separately
	// even though only one of them has focus at a time.
	eventsCursor int
	// eventsWindowTop is the index of the first row the events panel currently
	// shows. Unlike the connections table (which recomputes its window purely
	// from the cursor via visibleWindow, re-anchoring the cursor to whichever
	// edge it crosses), the events panel keeps this as its own state so the
	// cursor can move freely within an already-visible window — the window
	// itself only shifts once the cursor would otherwise leave it. See
	// eventsWindowStart.
	eventsWindowTop int
	// focus says which panel movement keys act on. zoomed gives that panel
	// the full height (border kept) and hides the other entirely; Esc
	// (Unzoom) is the only way back out, since FocusNext is a no-op while
	// zoomed.
	focus  panelFocus
	zoomed bool
	// eventsPanelRows is the events panel's own height in data rows (not
	// counting its border/column-header chrome) while not zoomed. It starts
	// at zero and is seeded to the eventsHeightFraction default by the first
	// WindowSizeMsg (see resizePanels), then adjusted by dragging the
	// divider. A later resize re-derives it from the *fraction* of the
	// two-panel area it occupied rather than carrying over an absolute row
	// count, so a terminal resize does not leave the split's proportions
	// stale.
	eventsPanelRows int
	// draggingDivider and dragRow track an in-progress click-drag on the
	// divider between the two panels; dragRow is the terminal row the drag
	// last moved through, so each motion event only has to apply its own
	// delta.
	draggingDivider bool
	dragRow         int

	width, height int
}

// NewModel builds the root model. ctx bounds the reverse-DNS lookups the view
// starts; res and hostnameCache may each be nil, in which case the hostname
// sources they provide are simply skipped.
func NewModel(ctx context.Context, agg *aggregate.Aggregator, res *dns.Resolver, hostnameCache *dpi.HostnameCache, interfaces []string) Model {
	input := textinput.New()
	input.Prompt = filterPrompt

	// A static cursor rather than a blinking one: blinking is driven by a
	// command per blink, which would have to be threaded back through Update
	// on every frame to keep going, and it would redraw the screen on its own
	// schedule alongside the tick. The filter is on screen for a few seconds
	// at a time and the prompt already says where the keyboard is pointing.
	input.Cursor.SetMode(cursor.CursorStatic)

	active := make(map[string]bool, len(interfaces))
	for _, name := range interfaces {
		active[name] = true
	}

	helpModel := help.New()
	helpModel.Styles = HelpStyles()

	return Model{
		agg:              agg,
		resolver:         res,
		hostnameCache:    hostnameCache,
		ctx:              ctx,
		interfaces:       interfaces,
		activeInterfaces: active,
		keys:             DefaultKeyMap(),
		styles:           DefaultStyles(),
		help:             helpModel,
		input:            input,
		showListening:    true,
		showTCP:          true,
		showUDP:          true,
		showIPv4:         true,
		showIPv6:         true,
		showPrivate:      true,
		sort:             SortPID,
	}
}

// Hostname returns the name to show for a row's destination, in priority
// order: the row's own DPI-detected hostname, the per-IP fallback cache
// (another connection to the same remote address — possibly serving a
// different hostname, but a reasonable guess when this one has none of its
// own), reverse DNS, and finally the bare address.
//
// r.Hostname is checked first and, if present, returned outright: it is a
// first-party, per-connection fact (see aggregate.Row.Hostname), unlike the
// fallback cache or a PTR record, either of which can be stale or simply
// wrong for this specific connection.
//
// It is safe to call from a render loop: dns.Resolver answers from its cache
// and starts anything it is missing in the background, so a frame is never
// held up by a query, and hostnameCache.Get never blocks either. A newly
// resolved name therefore appears on the next refresh rather than the moment
// it lands, which is the whole point: the table redraws every second anyway,
// so there is nothing for a notification to make happen sooner than the
// frame that was coming regardless.
//
// It is a package-level function, not just a Model method, so a plain-mode
// renderer could name destinations exactly the way the interactive table
// does without needing a Model of its own — see Model.resolveHostname, its
// bound form.
func Hostname(ctx context.Context, res *dns.Resolver, hostnameCache *dpi.HostnameCache, now time.Time, r aggregate.Row) string {
	if r.Hostname != "" {
		return r.Hostname
	}
	if r.RemoteAddr == "" {
		return r.RemoteAddr
	}
	if hostnameCache != nil {
		if host, ok := hostnameCache.Get(r.RemoteAddr, now); ok {
			return host
		}
	}
	if res == nil {
		return r.RemoteAddr
	}
	return res.Lookup(ctx, r.RemoteAddr)
}

// resolveHostname is Hostname bound to the resolver, cache and context this
// Model was built with, which is the form the table columns and the filter
// call it in.
func (m Model) resolveHostname(r aggregate.Row) string {
	return Hostname(m.ctx, m.resolver, m.hostnameCache, m.now, r)
}

// Init starts the render ticker.
func (m Model) Init() tea.Cmd {
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(TickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update handles input and tick messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resizePanels(msg.Width, msg.Height)

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tickMsg:
		// A paused model freezes its clock along with its rows: `now` is what
		// decides which rows render as closed, so letting it run on would have
		// a frozen table quietly grey itself out.
		if !m.paused {
			m.refresh(time.Time(msg))
		}
		return m, tick()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey applies one keypress.
//
// Keys are matched against the KeyMap rather than compared as strings, so the
// bindings the footer and the help overlay advertise are by construction the
// bindings that act — rebinding a key in one place cannot leave the other
// describing the old one.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While the filter input has the keyboard, a keypress is text and nothing
	// else. Nearly every binding below is a bare letter, so honouring them
	// during an edit would have "q" quit and "p" pause in the middle of a
	// word; the input is claimed first rather than fallen through to.
	if m.filtering {
		return m.handleFilterKey(msg)
	}

	// While the help overlay has the screen, it claims the keyboard the same
	// way: everything a normal keypress would act on — the cursor, grouping,
	// the filter — is out of sight underneath it, so only leaving the program
	// or closing the overlay make sense. Esc is handled as a raw key type
	// rather than through the KeyMap, the same way the filter input handles
	// it: there is nothing left for it to mean at the table level.
	if m.showHelp {
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help), msg.Type == tea.KeyEsc:
			m.showHelp = false
		}
		return m, nil
	}

	// The interface picker claims the keyboard the same way, for the same
	// reason: everything underneath it is out of sight, so only leaving the
	// program, closing the picker, or acting on the picker itself make sense.
	if m.showIfacePicker {
		return m.handleIfacePickerKey(msg)
	}

	// Esc only means anything while a panel is zoomed — everything else
	// below applies to whichever panel has focus regardless of zoom, since
	// zoom only changes layout, not input routing.
	if m.zoomed && key.Matches(msg, m.keys.Unzoom) {
		m.zoomed = false
		return m, nil
	}

	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keys.Up):
		m.moveSelection(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveSelection(1)
	case key.Matches(msg, m.keys.PageUp):
		m.moveSelection(-m.pageSize())
	case key.Matches(msg, m.keys.PageDown):
		m.moveSelection(m.pageSize())
	case key.Matches(msg, m.keys.Home):
		m.moveSelection(-m.selectionLen())
	case key.Matches(msg, m.keys.End):
		m.moveSelection(m.selectionLen())

	case key.Matches(msg, m.keys.FocusNext):
		if !m.zoomed {
			m.toggleFocus()
		}
	case key.Matches(msg, m.keys.Zoom):
		m.zoomed = true

	case key.Matches(msg, m.keys.Grouping):
		m.cycleGrouping()

	// `s` walks the whole cycle and `r` jumps straight between the two
	// bandwidth sorts the plan singles out; both land on the same SortKey, so
	// whichever the user reaches for, the other stays consistent with it.
	case key.Matches(msg, m.keys.Sort):
		m.setSort(m.sort.next())
	case key.Matches(msg, m.keys.RateSort):
		m.setSort(m.sort.toggleRate())

	case key.Matches(msg, m.keys.Filter):
		return m, m.openFilter()

	case key.Matches(msg, m.keys.ToggleListening):
		m.toggleListening()
	case key.Matches(msg, m.keys.ToggleTCP):
		m.toggleTCP()
	case key.Matches(msg, m.keys.ToggleUDP):
		m.toggleUDP()
	case key.Matches(msg, m.keys.ToggleIPv4):
		m.toggleIPv4()
	case key.Matches(msg, m.keys.ToggleIPv6):
		m.toggleIPv6()
	case key.Matches(msg, m.keys.TogglePrivate):
		m.togglePrivate()

	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
	case key.Matches(msg, m.keys.Interfaces):
		m.showIfacePicker = !m.showIfacePicker
	}
	return m, nil
}

// handleIfacePickerKey applies one keypress while the interface picker has
// the screen: Up/Down move the highlighted interface, space/enter flip it,
// and everything else that isn't leaving the program or closing the picker
// is ignored, the same claim on the keyboard the help overlay makes above.
func (m Model) handleIfacePickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Interfaces), msg.Type == tea.KeyEsc:
		m.showIfacePicker = false
	case key.Matches(msg, m.keys.Up):
		m.moveIfaceCursor(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveIfaceCursor(1)
	case msg.Type == tea.KeySpace, msg.Type == tea.KeyEnter:
		m.toggleActiveInterface()
	}
	return m, nil
}

// handleFilterKey applies one keypress while the filter input is open.
//
// The three keys it intercepts are matched on the key type rather than through
// the KeyMap, because in this context they do not mean what the KeyMap says
// they do. Enter is the drill key and esc pops the drill stack, yet here they
// have to commit and cancel the edit — milestone 6 left esc unclaimed at depth
// 0 for exactly this — and esc's other key, backspace, must stay a text edit
// rather than becoming a second way out. Reusing the bindings would therefore
// mean either drilling on commit or deleting a character on cancel.
//
// Ctrl-C is the exception that proves it: it is the terminal's own interrupt
// rather than a letter anyone types into a filter, and a text field that
// swallowed it would leave the user with no way out of the program at all.
func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.cancelFilter()
		return m, nil
	case tea.KeyEnter:
		m.commitFilter()
		return m, nil
	default:
		// Every other key is ordinary text input, handled below.
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)

	// The table narrows as the user types rather than on commit: an
	// incremental filter is how the user finds out whether what they have
	// typed so far picks out the row they are after, and it is what gives esc
	// something to undo.
	m.filter = m.input.Value()
	m.rebuild()
	return m, cmd
}

// openFilter hands the keyboard to the filter input.
//
// It starts empty rather than pre-filled with the filter in force, so that the
// commonest thing to do next — type a new filter — needs no clearing first,
// and so that committing an empty input is a plain, discoverable way to take a
// filter off again.
func (m *Model) openFilter() tea.Cmd {
	m.filterBefore = m.filter
	m.filtering = true

	m.input.SetValue("")

	// Focus's returned command starts the cursor blinking, which the static
	// cursor NewModel configures never needs in practice — but it is threaded
	// back to the caller anyway rather than assumed nil, so a future change to
	// that configuration cannot silently drop a command Bubble Tea expects.
	cmd := m.input.Focus()

	m.filter = ""
	m.rebuild()
	return cmd
}

// commitFilter accepts what was typed and returns the keyboard to the table.
// The filter itself is already in force, having been applied keystroke by
// keystroke.
func (m *Model) commitFilter() {
	m.filtering = false
	m.input.Blur()
}

// cancelFilter abandons the edit and puts back the filter it was opened over.
func (m *Model) cancelFilter() {
	m.filtering = false
	m.input.Blur()

	m.filter = m.filterBefore
	m.rebuild()
}

// moveCursor moves the selection by delta rows, clamping at both ends.
//
// It deliberately does not wrap: rows reorder under the cursor as traffic
// moves, so wrapping would fling the user to the far end of a table that may
// have just changed shape — and nethogs does not wrap either.
func (m *Model) moveCursor(delta int) {
	if len(m.rows) == 0 {
		m.cursor = 0
		return
	}
	m.cursor = clamp(m.cursor+delta, 0, len(m.rows)-1)
}

// moveSelection moves whichever panel currently has focus's own cursor by
// delta: the connections table's cursor, or the events panel's eventsCursor.
// Zoom does not affect this routing — only which panels are drawn.
func (m *Model) moveSelection(delta int) {
	if m.focus == focusEvents {
		m.moveEventsCursor(delta)
		return
	}
	m.moveCursor(delta)
}

// moveEventsCursor moves the events panel's own cursor by delta, clamping at
// both ends the same way moveCursor does for the connections table, then
// brings eventsWindowTop along just far enough to keep the cursor visible.
func (m *Model) moveEventsCursor(delta int) {
	n := m.events.len()
	if n == 0 {
		m.eventsCursor = 0
		m.eventsWindowTop = 0
		return
	}
	m.eventsCursor = clamp(m.eventsCursor+delta, 0, n-1)
	m.eventsWindowTop = eventsWindowStart(m.eventsWindowTop, m.eventsCursor, n, m.eventsRowLines())
}

// selectionLen is how many rows the focused panel's cursor moves against —
// what Home/End clamp to.
func (m Model) selectionLen() int {
	if m.focus == focusEvents {
		return m.events.len()
	}
	return len(m.rows)
}

// toggleFocus swaps which of the two panels the keyboard acts on.
func (m *Model) toggleFocus() {
	if m.focus == focusConnections {
		m.focus = focusEvents
	} else {
		m.focus = focusConnections
	}
}

// moveIfaceCursor moves the interface picker's highlighted row by delta,
// clamping at both ends the same way moveCursor does for the table.
func (m *Model) moveIfaceCursor(delta int) {
	if len(m.interfaces) == 0 {
		m.ifaceCursor = 0
		return
	}
	m.ifaceCursor = clamp(m.ifaceCursor+delta, 0, len(m.interfaces)-1)
}

// toggleActiveInterface flips whether the highlighted interface's rows are
// shown, redrawing immediately rather than waiting for the next tick — the
// same immediacy toggleListening/toggleTCP/toggleUDP already have.
func (m *Model) toggleActiveInterface() {
	if m.ifaceCursor < 0 || m.ifaceCursor >= len(m.interfaces) {
		return
	}
	name := m.interfaces[m.ifaceCursor]
	m.activeInterfaces[name] = !m.activeInterfaces[name]
	m.rebuild()
}

// pageSize is how far PgUp/PgDn move the focused panel's cursor: one
// screenful of whichever panel that is, so that paging lines up with what
// the user can actually see. Until the first tea.WindowSizeMsg arrives there
// is no screenful to measure, so it falls back to a fixed jump.
func (m Model) pageSize() int {
	connRows, eventsRows := m.layout()
	n := connRows
	if m.focus == focusEvents {
		n = eventsRows
	}
	if n > 0 {
		return n
	}
	return defaultPageSize
}

// layout computes the data-row budget for the connections and events
// panels, given the terminal height, the zoom/focus state, and
// eventsPanelRows. It is the one place that arithmetic is spelled out, so
// that View's rendering and the mouse divider hit-test can never disagree.
//
// The footer always takes exactly one line, even while a panel is zoomed.
// While zoomed, the focused panel gets everything else and the other panel
// is not rendered at all (0 rows, no border drawn). Otherwise the events
// panel gets eventsPanelRows data rows (floored at minPanelDataRows) and
// connections gets whatever remains, floored the same way — trading away
// some of the events panel's rows first, since it is the one the user (or
// the default fraction) sized last.
func (m Model) layout() (connRows, eventsRows int) {
	if m.height <= 0 {
		return 0, 0
	}

	if m.zoomed {
		avail := m.splitTotalLines()
		if m.focus == focusEvents {
			return 0, max(avail-eventsChromeLines, 1)
		}
		return max(avail-connChromeLines, 1), 0
	}

	total := m.splitTotalLines()
	eventsRows = max(m.eventsPanelRows, minPanelDataRows)
	connRows = total - connChromeLines - (eventsRows + eventsChromeLines)
	if connRows < minPanelDataRows {
		connRows = minPanelDataRows
		eventsRows = max(total-connChromeLines-minPanelDataRows-eventsChromeLines, minPanelDataRows)
	}
	return connRows, eventsRows
}

// splitTotalLines is the total lines available to both panels' chrome and
// data combined: the terminal height minus the one line the footer always
// takes.
func (m Model) splitTotalLines() int {
	return max(m.height-1, 0)
}

// eventsRowLines is how many data rows the events panel currently has room
// for, per layout.
func (m Model) eventsRowLines() int {
	_, eventsRows := m.layout()
	return eventsRows
}

// resizePanels applies a new terminal size. eventsPanelRows is re-derived
// from the *fraction* of the two-panel area it occupied before the resize,
// rather than carried over as an absolute row count, so that a terminal
// resize does not leave the split's proportions stale; the very first resize
// has no prior fraction to preserve, so it seeds the eventsHeightFraction
// default instead.
func (m *Model) resizePanels(width, height int) {
	frac := 1.0 / float64(eventsHeightFraction)
	if m.eventsPanelRows > 0 {
		if prevTotal := m.splitTotalLines(); prevTotal > 0 {
			frac = float64(m.eventsPanelRows+eventsChromeLines) / float64(prevTotal)
		}
	}

	m.width, m.height = width, height

	total := m.splitTotalLines()
	m.eventsPanelRows = max(int(float64(total)*frac)-eventsChromeLines, minPanelDataRows)
}

// dividerRow is the terminal row of the line between the two panels — the
// connections panel's own bottom border — that a mouse press has to land on
// to start a divider drag. It returns -1 while zoomed, since there is no
// divider to grab: only one panel is ever on screen.
func (m Model) dividerRow() int {
	if m.zoomed {
		return -1
	}
	connRows, _ := m.layout()
	return connChromeLines + connRows - 1
}

// adjustEventsPanelRows grows or shrinks the events panel by delta data
// rows, clamped so neither panel can shrink below minPanelDataRows.
func (m *Model) adjustEventsPanelRows(delta int) {
	total := m.splitTotalLines()
	maxRows := max(total-connChromeLines-eventsChromeLines-minPanelDataRows, minPanelDataRows)
	m.eventsPanelRows = clamp(m.eventsPanelRows+delta, minPanelDataRows, maxRows)
}

// handleMouse applies one mouse event: pressing on the divider between the
// two panels starts a drag, motion while dragging resizes the events panel,
// and release ends it. Mouse input is ignored entirely while zoomed, since
// the divider it drags does not exist then.
func (m Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.zoomed {
		return m, nil
	}

	switch msg.Action {
	case tea.MouseActionPress:
		if msg.Y == m.dividerRow() {
			m.draggingDivider = true
			m.dragRow = msg.Y
		}
	case tea.MouseActionMotion:
		if m.draggingDivider {
			delta := msg.Y - m.dragRow
			m.dragRow = msg.Y
			// Dragging the divider up (delta < 0) grows the events panel.
			m.adjustEventsPanelRows(-delta)
		}
	case tea.MouseActionRelease:
		m.draggingDivider = false
	}
	return m, nil
}

// cycleGrouping advances the grouping to the next of the three states —
// ungrouped, by PID, by process name — wrapping back round to ungrouped.
func (m *Model) cycleGrouping() {
	m.grouping = m.grouping.Next()
	m.resetRows()
	m.rebuild()
}

// setSort changes the sort key and reorders what is already on screen, so the
// new order is visible on the next frame rather than at the next tick.
func (m *Model) setSort(k SortKey) {
	m.sort = k
	m.rebuild()
}

// toggleListening flips whether LISTEN-state rows are shown, redrawing
// immediately rather than waiting for the next tick — the same immediacy
// grouping and sort changes get.
func (m *Model) toggleListening() {
	m.showListening = !m.showListening
	m.rebuild()
}

// toggleTCP flips whether TCP rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleTCP() {
	m.showTCP = !m.showTCP
	m.rebuild()
}

// toggleUDP flips whether UDP rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleUDP() {
	m.showUDP = !m.showUDP
	m.rebuild()
}

// toggleIPv4 flips whether IPv4 rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleIPv4() {
	m.showIPv4 = !m.showIPv4
	m.rebuild()
}

// toggleIPv6 flips whether IPv6 rows are shown, the same way toggleListening
// flips LISTEN rows.
func (m *Model) toggleIPv6() {
	m.showIPv6 = !m.showIPv6
	m.rebuild()
}

// togglePrivate flips whether rows with a private remote address are shown,
// the same way toggleListening flips LISTEN rows.
func (m *Model) togglePrivate() {
	m.showPrivate = !m.showPrivate
	m.rebuild()
}

// refresh pulls a fresh snapshot from the aggregator and rebuilds the table
// from it.
func (m *Model) refresh(now time.Time) {
	// Test fixtures routinely build a Model with no live aggregator behind it,
	// so a tick reaching one must do nothing rather than panic.
	if m.agg == nil {
		return
	}

	snap := m.agg.Refresh(now)
	// Copied out before m.snap is overwritten: Refresh drains these five
	// streams fresh every call and does not retain them (see Snapshot's own
	// doc comment), so this is the only chance to keep anything that
	// accumulated since the previous tick.
	m.appendEvents(snap)
	m.snap = snap
	m.now = now
	m.rebuild()
}

// rebuild recomputes the visible rows from the snapshot the model already
// holds.
//
// It never asks the aggregator for fresh data: Refresh recomputes rates
// against a newer clock and ages rows out, which is precisely what pause
// exists to prevent, so a grouping or sort change made while paused must be
// able to redraw the frozen data rather than thaw it.
//
// Taking the rows apart from where they came from is also what lets the parts
// with all the subtlety in them — the filter, the sort and the cursor — be
// exercised with hand-built inputs, no live capture and no root.
func (m *Model) rebuild() {
	rows := aggregate.Rows(m.snap, m.grouping)
	rows = filterListening(rows, m.showListening)
	rows = filterProto(rows, m.showTCP, m.showUDP)
	rows = filterIPFamily(rows, m.showIPv4, m.showIPv6)
	rows = filterPrivate(rows, m.showPrivate)
	rows = filterIface(rows, m.activeInterfaces)
	rows = filterRows(rows, m.filter, m.resolveHostname)
	sortRows(rows, m.sort)
	m.setRows(rows)
}

// setRows installs a freshly computed row set, keeping the cursor on the row
// it was already on.
func (m *Model) setRows(rows []aggregate.Row) {
	key := m.selectedKey()
	m.rows = rows
	m.cursor = cursorFor(rows, key, m.cursor)
}

// resetRows drops the rows on screen so that the next rebuild starts from the
// top. Changing mode or grouping changes what a row *is*, so there is no row
// left for the cursor to hold onto and keeping its index would land it
// somewhere arbitrary.
func (m *Model) resetRows() {
	m.rows, m.cursor = nil, 0
}

// selectedKey is the Key of the row under the cursor, or "" when there is no
// selection to preserve.
func (m Model) selectedKey() string {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return ""
	}
	return m.rows[m.cursor].Key
}

// cursorFor finds where the row identified by key ended up in a freshly built
// row set.
//
// Rows reorder on nearly every refresh, so the cursor has to track the row the
// user selected rather than the position it happened to be in — otherwise the
// selection slides onto whatever row overtook it, and pressing enter opens
// something the user was not pointing at. A row that has aged out entirely has
// no new index to find, so the old position is the next best thing: the
// neighbours of a vanished row are what the user was looking at.
func cursorFor(rows []aggregate.Row, key string, fallback int) int {
	if len(rows) == 0 {
		return 0
	}
	if key != "" {
		for i, r := range rows {
			if r.Key == key {
				return i
			}
		}
	}
	return clamp(fallback, 0, len(rows)-1)
}

// clamp confines v to [lo, hi].
func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}

// View renders the header bar and the table (or the help overlay in its
// place) inside the Connections panel, the events feed inside the Events
// panel below it, and the footer below both, as one frame no taller than the
// terminal. While zoomed only the focused panel's own bordered box is drawn,
// per layout.
func (m Model) View() string {
	connRows, eventsRows := m.layout()

	var lines []string
	if connRows > 0 {
		lines = append(lines, m.viewConnPanel()...)
	}
	if eventsRows > 0 {
		lines = append(lines, m.viewEventsPanel()...)
	}
	lines = append(lines, m.viewFooter())

	// Nothing may be wider than the terminal, and the pieces cannot all
	// guarantee that themselves: the column layout has a floor it refuses to
	// shrink past, and the help bubble stops dropping columns while it is
	// still overflowing. Clipping here catches all of them in one place, and
	// it has to be done: an over-wide line wraps, and every wrapped line
	// pushes the footer further off the bottom of the screen.
	//
	// Only the lines that actually overflow are put through it: clipping
	// rewrites a line's styling cell by cell, which is a lot of escape
	// sequences to send every second for lines that already fit.
	clip := lipgloss.NewStyle().MaxWidth(m.viewWidth())
	for i, l := range lines {
		if lipgloss.Width(l) > m.viewWidth() {
			lines[i] = clip.Render(l)
		}
	}

	// A frame taller than the terminal would scroll the header off the top, so
	// clip rather than let that happen on a very short window.
	if m.height > 0 && len(lines) > m.height {
		lines = lines[:m.height]
	}
	return strings.Join(lines, "\n")
}

// viewConnPanel renders the Connections panel: the header bar and the table
// (or the help overlay/interface picker in its place), inside a bordered box
// sized from rowLines/layout.
func (m Model) viewConnPanel() []string {
	body := []string{m.viewHeader()}
	switch {
	case m.showHelp:
		body = append(body, m.viewHelp()...)
	case m.showIfacePicker:
		body = append(body, m.viewIfacePicker()...)
	default:
		body = append(body, m.viewTable()...)
	}

	focused := m.zoomed || m.focus == focusConnections
	panel := renderPanel(m.styles, panelTitle, m.viewWidth(), len(body)+panelBorderHeight, strings.Join(body, "\n"), focused)
	return strings.Split(panel, "\n")
}

// viewEventsPanel renders the Events panel: the SYN/RST/DNS-query/DNS-error
// feed, inside a bordered box the same way viewConnPanel builds its own.
func (m Model) viewEventsPanel() []string {
	body := m.viewEvents()
	focused := m.zoomed || m.focus == focusEvents
	panel := renderPanel(m.styles, eventsPanelTitle, m.viewWidth(), len(body)+panelBorderHeight, strings.Join(body, "\n"), focused)
	return strings.Split(panel, "\n")
}

// viewHeader renders the title bar: the current grouping on the left, the
// sort/filter status and the toggle badges pushed out to the right.
func (m Model) viewHeader() string {
	// The header style already pads a cell either side, so the segments hung
	// off it must not add a leading space of their own.
	left := m.styles.Header.Render(appName + " · " + m.grouping.String())

	// The sort key is named here as well as marked on the column it reads,
	// because that column is one of the first to be dropped on a narrow
	// terminal and the row order would otherwise have no explanation at all.
	//
	// A filter in force is named alongside it for the same kind of reason,
	// and a stronger one: rows silently absent from the table look exactly
	// like traffic that stopped, and unlike the sort there is no mark
	// anywhere else on the screen to give it away.
	label := "sort: " + m.sort.String()
	if m.filter != "" {
		label = "filter: " + truncate(m.filter, maxFilterLabel) + " · " + label
	}
	status := m.styles.Header.Render(label)

	onOff := func(enable bool, on, off string) string {
		if enable {
			return m.styles.Live.Render(on)
		}
		return m.styles.Paused.Render(off)
	}

	right := strings.Join([]string{
		status,
		onOff(m.showListening, "LISTEN", "!LISTEN"),
		onOff(m.showTCP, "TCP", "!TCP"),
		onOff(m.showUDP, "UDP", "!UDP"),
		onOff(m.showIPv4, "IPV4", "!IPV4"),
		onOff(m.showIPv6, "IPV6", "!IPV6"),
		onOff(m.showPrivate, "PRIV", "!PRIV"),
		onOff(m.allInterfacesActive(), "IFACE", "!IFACE"),
		onOff(!m.paused, "live", "PAUSED"),
	}, " · ")

	return joinEnds(left, right, m.contentWidth())
}

// allInterfacesActive reports whether every known interface is currently
// shown, mirroring the LISTEN/TCP/UDP toggles' convention that true is the
// unfiltered state.
func (m Model) allInterfacesActive() bool {
	for _, name := range m.interfaces {
		if !m.activeInterfaces[name] {
			return false
		}
	}
	return true
}

// viewTable renders the column titles and as many rows as fit, keeping the
// cursor on screen.
func (m Model) viewTable() []string {
	cols := fitColumns(tableColumns(m.grouping, m.resolveHostname, m.now), m.contentWidth())
	lines := []string{m.styles.ColumnHeader.Render(tableHeader(cols, m.sort))}

	if len(m.rows) == 0 {
		lines = append(lines, m.styles.Breadcrumb.Render(m.emptyBody()))
		return m.fit(lines)
	}

	start, end := visibleWindow(len(m.rows), m.cursor, m.rowLines())
	for i, line := range renderRows(m.rows[start:end], cols) {
		row := m.rows[start+i]

		// Dim first, then invert: a closed row that also happens to be under
		// the cursor should still read as both.
		if row.Closed(m.now) {
			line = m.styles.Closed.Render(line)
		}
		if start+i == m.cursor {
			line = m.styles.Selected.Render(line)
		}
		lines = append(lines, line)
	}
	return m.fit(lines)
}

// emptyBody explains a table with no rows in it. A filter is a likelier
// reason for one than an idle capture, and it has its own way out, so the two
// are worded separately rather than the filtered case claiming the capture
// has seen nothing.
func (m Model) emptyBody() string {
	if m.filter != "" {
		return emptyFilterMessage
	}
	return emptyMessage
}

// viewHelp renders the full key reference in place of the table.
func (m Model) viewHelp() []string {
	h := m.help
	h.ShowAll = true
	h.Width = m.contentWidth()

	helpLines := strings.Split(h.FullHelpView(m.keys.FullHelp()), "\n")
	lines := make([]string, 0, 2+len(helpLines))
	lines = append(lines, m.styles.ColumnHeader.Render("Key reference"), "")
	lines = append(lines, helpLines...)
	return m.fit(lines)
}

// viewIfacePicker renders the interface checklist in place of the table: one
// checkbox line per interface capture was started with, the highlighted one
// styled the same way the table's own selected row is.
func (m Model) viewIfacePicker() []string {
	lines := make([]string, 0, 2+len(m.interfaces))
	lines = append(lines, m.styles.ColumnHeader.Render("Interfaces"), "")

	for i, name := range m.interfaces {
		mark := "[ ]"
		if m.activeInterfaces[name] {
			mark = "[x]"
		}
		line := pad(mark+" "+name, m.contentWidth(), alignLeft, false)
		if i == m.ifaceCursor {
			line = m.styles.Selected.Render(line)
		}
		lines = append(lines, line)
	}
	return m.fit(lines)
}

// viewFooter renders the context-sensitive key hints, or the filter input in
// their place while one is being typed.
func (m Model) viewFooter() string {
	if m.filtering {
		return m.viewFilterInput()
	}

	h := m.help
	h.ShowAll = false

	// The footer style pads a cell either side, which is width the hint line
	// itself cannot use.
	h.Width = max(m.viewWidth()-2, 1)

	return m.styles.Footer.Render(h.ShortHelpView(m.footerKeys()))
}

// viewFilterInput renders the filter line the `/` key opens.
//
// It takes the footer's line rather than a line of its own: the footer is
// where the eye already goes to find out what can be pressed, the hints it
// displaces are precisely the ones that do not apply while the keyboard
// belongs to the input, and borrowing a line the frame already has costs the
// table no rows. When the typed filter grows long enough to reach the hint,
// joinEnds drops the hint rather than wrapping — by then it has been read.
func (m Model) viewFilterInput() string {
	// The footer style pads a cell either side, which is width the line
	// itself cannot use.
	w := max(m.viewWidth()-2, 1)
	return m.styles.Footer.Render(joinEnds(m.input.View(), filterHint, w))
}

// footerKeys picks the hints for the current context: the standard set,
// plus `/` once a filter is in force. It is the one state the user can put
// the table into that hides rows, so it is the one they may need to undo
// without having been told how; the rest of the time the footer is better
// spent on the keys that do something to what is on screen.
func (m Model) footerKeys() []key.Binding {
	keys := m.keys.ShortHelp()
	if m.filter == "" {
		return keys
	}

	out := make([]key.Binding, 0, len(keys)+1)
	for _, k := range keys {
		// Ahead of the help key, so the hints that change the table stay
		// together and the two that are about the session stay last.
		if k.Help() == m.keys.Help.Help() {
			out = append(out, m.keys.Filter)
		}
		out = append(out, k)
	}
	return out
}

// fit pads or trims the body to exactly the number of lines the frame has room
// for, which is what pins the footer to the bottom of the terminal. A window
// whose size is not known yet gets the body unchanged.
func (m Model) fit(lines []string) []string {
	return fitLines(lines, m.rowLines())
}

// fitLines is fit's underlying arithmetic, shared with fitEvents: n counts
// data rows, the column-title line sits above them, and n<=0 means the frame
// size is not known yet, so lines are returned unchanged.
func fitLines(lines []string, n int) []string {
	if n <= 0 {
		return lines
	}

	n++
	for len(lines) < n {
		lines = append(lines, "")
	}
	return lines[:n]
}

// rowLines is how many connections-table rows the terminal has room for, per
// layout, or 0 when the terminal size is not known yet and every row is
// drawn.
func (m Model) rowLines() int {
	connRows, _ := m.layout()
	return connRows
}

// viewWidth is the terminal width, falling back to a sensible default until
// the first tea.WindowSizeMsg arrives.
func (m Model) viewWidth() int {
	if m.width <= 0 {
		return defaultWidth
	}
	return m.width
}

// contentWidth is the width available to whatever renders inside the
// panel — the header line and the table — once renderPanel's own border and
// padding have taken their share of viewWidth.
func (m Model) contentWidth() int {
	return clamp(m.viewWidth()-panelBorderWidth, 1, m.viewWidth())
}

// visibleWindow returns the half-open range of rows to draw so that the cursor
// stays on screen. A limit of zero or less means "no limit".
func visibleWindow(n, cursor, limit int) (start, end int) {
	if limit <= 0 || n <= limit {
		return 0, n
	}

	// Scroll only far enough to bring the cursor back into view, so the rows
	// around it stay put instead of the whole table jumping.
	start = 0
	if cursor >= limit {
		start = cursor - limit + 1
	}
	if start+limit > n {
		start = n - limit
	}
	return start, start + limit
}

// joinEnds lays left at the start of a w-wide line and right at its end. If
// the two cannot both fit it keeps the left-hand segment, since wrapping would
// cost a line the table needs.
func joinEnds(left, right string, w int) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + strings.Repeat(" ", gap) + right
}
