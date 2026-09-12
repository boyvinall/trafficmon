// Package tui implements the Bubble Tea front end.
package tui

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

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
