// Package ui implements the Bubble Tea front end.
package ui

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

	"github.com/boyvinall/mac-nethogs/aggregate"
	"github.com/boyvinall/mac-nethogs/dns"
)

// TickInterval is the render cadence. It is deliberately independent of both
// the capture rate and the process poll rate.
const TickInterval = time.Second

// appName is the title shown at the left of the header bar.
const appName = "mac-nethogs"

// chromeLines is how many lines View spends on furniture rather than data: the
// header bar, the column titles and the footer.
const chromeLines = 3

// defaultPageSize is how far PgUp/PgDn move the cursor before the terminal
// height is known and a real screenful can be measured.
const defaultPageSize = 10

// emptyMessage stands in for the table body before any traffic has been seen,
// so a working but idle capture does not look like a broken one.
const emptyMessage = "  (no traffic yet)"

// emptyScopeMessage stands in for the table body of a drilled-in view with
// nothing left in it — the process exited, or the host went quiet. It is
// worded differently from emptyMessage because "no traffic yet" would be
// plainly wrong with a busy table one esc away, and because the way out is the
// only thing left to do here.
const emptyScopeMessage = "  (nothing left in this view — esc to go back)"

// emptyFilterMessage stands in for the table body of a view whose filter
// matches nothing. It takes precedence over the other two: a filter is
// something the user typed a moment ago and can undo, so it is far and away
// the likeliest explanation for an empty table, and "no traffic yet" would be
// a flat contradiction of the header bar naming the filter that emptied it.
const emptyFilterMessage = "  (nothing matches the filter — / to change it)"

// minBreadcrumbWidth is the narrowest breadcrumb worth rendering. Below it a
// drill path says nothing at all, so the header spends the cells on the status
// instead.
const minBreadcrumbWidth = 12

// breadcrumbPrefix separates the drill path from the mode label it hangs off.
const breadcrumbPrefix = "› "

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

// Model is the root Bubble Tea model.
type Model struct {
	agg *aggregate.Aggregator
	// resolver turns remote addresses into hostnames. It answers from cache
	// and never blocks, so View may call it freely; see dns.Resolver.
	resolver *dns.Resolver
	// ctx is the program's lifetime, held so that the background lookups the
	// render loop starts are wound up with it. Bubble Tea hands Update and
	// View no context of their own, and the alternative — resolving against
	// context.Background — would leave Lookup's cancellation permanently
	// theoretical.
	ctx context.Context

	iface  string
	keys   KeyMap
	styles Styles
	// help renders both the footer hint line and the `?` overlay from keys,
	// so the two can never drift apart from the bindings Update acts on.
	help help.Model

	stack    *Stack
	grouping aggregate.Grouping
	sort     SortKey

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

	width, height int
}

// NewModel builds the root model. ctx bounds the reverse-DNS lookups the view
// starts; res may be nil, in which case destinations are never named.
func NewModel(ctx context.Context, agg *aggregate.Aggregator, res *dns.Resolver, iface string) Model {
	input := textinput.New()
	input.Prompt = filterPrompt

	// A static cursor rather than a blinking one: blinking is driven by a
	// command per blink, which would have to be threaded back through Update
	// on every frame to keep going, and it would redraw the screen on its own
	// schedule alongside the tick. The filter is on screen for a few seconds
	// at a time and the prompt already says where the keyboard is pointing.
	input.Cursor.SetMode(cursor.CursorStatic)

	return Model{
		agg:      agg,
		resolver: res,
		ctx:      ctx,
		iface:    iface,
		keys:     DefaultKeyMap(),
		styles:   DefaultStyles(),
		help:     help.New(),
		stack:    NewStack(ModeProcess),
		input:    input,
	}
}

// hostname is the reverse-resolved name for a row's destination, falling back
// to the bare address until — or unless — one is known.
//
// It is safe to call from the render loop: dns.Resolver answers from its cache
// and starts anything it is missing in the background, so a frame is never
// held up by a query. A newly resolved name therefore appears on the next tick
// rather than the moment it lands, which is the whole point: the table redraws
// every second anyway, so there is nothing for a notification to make happen
// sooner than the frame that was coming regardless.
func (m Model) hostname(r aggregate.Row) string {
	if r.RemoteAddr == "" || m.resolver == nil {
		return r.RemoteAddr
	}
	return m.resolver.Lookup(m.ctx, r.RemoteAddr)
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
		m.width, m.height = msg.Width, msg.Height

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

	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit

	case key.Matches(msg, m.keys.Up):
		m.moveCursor(-1)
	case key.Matches(msg, m.keys.Down):
		m.moveCursor(1)
	case key.Matches(msg, m.keys.PageUp):
		m.moveCursor(-m.pageSize())
	case key.Matches(msg, m.keys.PageDown):
		m.moveCursor(m.pageSize())
	case key.Matches(msg, m.keys.Home):
		m.moveCursor(-len(m.rows))
	case key.Matches(msg, m.keys.End):
		m.moveCursor(len(m.rows))

	case key.Matches(msg, m.keys.Mode):
		m.toggleMode()
	case key.Matches(msg, m.keys.Grouping):
		m.toggleGrouping()

	case key.Matches(msg, m.keys.Enter):
		m.drillIn()
	case key.Matches(msg, m.keys.Back):
		m.drillOut()

	// `s` walks the whole cycle and `r` jumps straight between the two
	// bandwidth sorts the plan singles out; both land on the same SortKey, so
	// whichever the user reaches for, the other stays consistent with it.
	case key.Matches(msg, m.keys.Sort):
		m.setSort(m.sort.next())
	case key.Matches(msg, m.keys.RateSort):
		m.setSort(m.sort.toggleRate())

	case key.Matches(msg, m.keys.Filter):
		m.openFilter()

	case key.Matches(msg, m.keys.Pause):
		m.paused = !m.paused
	case key.Matches(msg, m.keys.Help):
		m.showHelp = !m.showHelp
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
func (m *Model) openFilter() {
	m.filterBefore = m.filter
	m.filtering = true

	m.input.SetValue("")

	// Focus hands back a command to start the cursor blinking, which the
	// static cursor NewModel configures never needs; it is nil here.
	m.input.Focus()

	m.filter = ""
	m.rebuild()
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

// pageSize is how far PgUp/PgDn move the cursor: one screenful, so that paging
// lines up with what the user can actually see. Until the first
// tea.WindowSizeMsg arrives there is no screenful to measure, so it falls back
// to a fixed jump.
func (m Model) pageSize() int {
	if n := m.rowLines(); n > 0 {
		return n
	}
	return defaultPageSize
}

// toggleMode swaps the top-level view between processes and destinations.
//
// It does nothing once the user has drilled in. Tab means "show me the other
// top-level view", and inside a drill-down the other view of the same scope is
// exactly what Enter already offers; silently unwinding the drill path on a
// key that normally does something small would throw away navigation the user
// did deliberately. Esc is the way back out, and footerKeys stops offering tab
// at depth so the key is not advertised where it has no effect.
func (m *Model) toggleMode() {
	if m.stack.Depth() > 0 {
		return
	}

	if m.stack.Top().Mode == ModeProcess {
		m.stack.SetMode(ModeDestination)
	} else {
		m.stack.SetMode(ModeProcess)
	}
	m.resetRows()
	m.rebuild()
}

// toggleGrouping switches the by-destination view between one row per remote
// IP and one per remote IP:port. The by-process view has no destinations to
// group, so there it is a no-op rather than a change that only shows up later.
func (m *Model) toggleGrouping() {
	if m.stack.Top().Mode != ModeDestination {
		return
	}

	if m.grouping == aggregate.GroupByIP {
		m.grouping = aggregate.GroupByIPPort
	} else {
		m.grouping = aggregate.GroupByIP
	}
	m.resetRows()
	m.rebuild()
}

// drillIn opens the selected row in the opposite view, scoped to it: a process
// row leads to that process's destinations, a destination row to the processes
// talking to it. It is the enter half of the drill-down stack.
//
// The cursor is reset rather than carried over, because the rows either side
// of the drill are not the same kind of thing — the row the user was pointing
// at does not exist in the view they land in — so there is no selection to
// preserve and holding the index would land them somewhere arbitrary.
func (m *Model) drillIn() {
	// An empty table has nothing to drill into, and the cursor is allowed to
	// sit outside the rows — no selection at all is a state the view renders
	// quite happily — so neither can be assumed away here.
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return
	}

	var f Frame
	switch m.stack.Top().Mode {
	case ModeProcess:
		f = processFrame(m.rows[m.cursor])
	case ModeDestination:
		f = destinationFrame(m.rows[m.cursor], m.grouping)
	}

	// Drilling into a scope the stack already carries would add a level
	// showing the rows underneath it unchanged. See Stack.HasScope.
	if m.stack.HasScope(f.Scope) {
		return
	}

	m.stack.Push(f)
	m.resetRows()
	m.rebuild()
}

// drillOut pops back to the view the user drilled down from.
//
// At the top level there is nothing to pop and it does nothing at all: the
// footer does not offer esc there, and leaving the key unclaimed at depth 0 is
// what lets milestone 7 give it the "cancel the filter input" meaning without
// having to take it off the drill-down stack first.
func (m *Model) drillOut() {
	if m.stack.Depth() == 0 {
		return
	}

	m.stack.Pop()
	m.resetRows()
	m.rebuild()
}

// setSort changes the sort key and reorders what is already on screen, so the
// new order is visible on the next frame rather than at the next tick.
func (m *Model) setSort(k SortKey) {
	m.sort = k
	m.rebuild()
}

// refresh pulls a fresh snapshot from the aggregator and rebuilds the table
// from it.
func (m *Model) refresh(now time.Time) {
	m.snap = m.agg.Refresh(now)
	m.now = now
	m.rebuild()
}

// rebuild recomputes the visible rows from the snapshot the model already
// holds.
//
// It never asks the aggregator for fresh data: Refresh recomputes rates
// against a newer clock and ages rows out, which is precisely what pause
// exists to prevent, so a mode or sort change made while paused must be able
// to redraw the frozen data rather than thaw it.
//
// Taking the rows apart from where they came from is also what lets the parts
// with all the subtlety in them — the filter, the sort and the cursor — be
// exercised with hand-built inputs, no live capture and no root.
func (m *Model) rebuild() {
	snap := m.stack.Apply(m.snap)

	var rows []aggregate.Row
	switch m.stack.Top().Mode {
	case ModeProcess:
		rows = aggregate.ByProcess(snap)
	case ModeDestination:
		rows = aggregate.ByDestination(snap, m.grouping)
	}

	rows = filterRows(rows, m.filter, m.hostname)
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

// View renders the header bar, the table (or the help overlay in its place)
// and the footer as one frame no taller than the terminal.
func (m Model) View() string {
	lines := []string{m.viewHeader()}
	if m.showHelp {
		lines = append(lines, m.viewHelp()...)
	} else {
		lines = append(lines, m.viewTable()...)
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

// viewHeader renders the title bar: the current mode and drill-down breadcrumb
// on the left, the capture interface and status pushed out to the right.
func (m Model) viewHeader() string {
	// The header style already pads a cell either side, so the segments hung
	// off it must not add a leading space of their own.
	left := m.styles.Header.Render(appName + " · " + modeLabel(m.stack.Top().Mode, m.grouping))

	// The sort key is named here as well as marked on the column it reads,
	// because that column is one of the first to be dropped on a narrow
	// terminal and the row order would otherwise have no explanation at all.
	//
	// A filter in force is named alongside it for the same kind of reason,
	// and a stronger one: rows silently absent from the table look exactly
	// like traffic that stopped, and unlike the sort there is no mark
	// anywhere else on the screen to give it away.
	label := "sort: " + m.sort.String() + " · " + m.iface + " ·"
	if m.filter != "" {
		label = "filter: " + truncate(m.filter, maxFilterLabel) + " · " + label
	}
	status := m.styles.Breadcrumb.Render(label)

	// The capture flag is the other half of the right-hand end, and the two
	// are kept apart because they are not equally expendable: the sort and
	// interface are said elsewhere on the screen, whereas a frozen table looks
	// exactly like a live one that has gone quiet and only this says which.
	flag := m.styles.Breadcrumb.Render(" live")
	if m.paused {
		flag = m.styles.Paused.Render(" PAUSED ")
	}
	right := status + flag

	if path := m.stack.Breadcrumb(); path != "" {
		// The breadcrumb is the one segment of the bar with no bound on its
		// length — it grows a step with every level drilled — so it is given
		// what the other segments leave rather than allowed to shove them off
		// the end. Where that is not enough to say anything, the status half
		// hands its cells over: which scope is on screen is the more useful of
		// the two, and it only does so if that actually buys a breadcrumb.
		//
		// " live" goes with it, being the absence of news; " PAUSED " never
		// does.
		spare := ""
		if m.paused {
			spare = flag
		}

		room := m.viewWidth() - lipgloss.Width(left) - lipgloss.Width(right) - 1
		bare := m.viewWidth() - lipgloss.Width(left) - lipgloss.Width(spare) - 1
		if room < minBreadcrumbWidth && bare >= minBreadcrumbWidth {
			right, room = spare, bare
		}

		if seg := breadcrumbSegment(path, m.stack.Top().Mode, room); seg != "" {
			left += m.styles.Breadcrumb.Render(seg)
		}
	}

	return joinEnds(left, right, m.viewWidth())
}

// breadcrumbSegment renders the drill path into at most w cells of the header
// bar.
//
// With room it reads as the plan writes it — "› Process: Chrome (pid 4821) →
// Destinations" — the trailing noun naming what the view the user landed in is
// a list of. That noun is the first thing given up when the path outgrows the
// bar, because the mode label at the other end of the same bar already says
// it; only then is the path itself cut, and from the left, so that the
// innermost scope — the one the rows on screen are actually filtered by —
// survives.
func breadcrumbSegment(path string, mode Mode, w int) string {
	// Too narrow to read: the cells are better spent on the status, and a
	// breadcrumb clipped to a couple of characters is worse than none.
	if w < minBreadcrumbWidth {
		return ""
	}

	noun := "Processes"
	if mode == ModeDestination {
		noun = "Destinations"
	}

	if full := breadcrumbPrefix + path + " → " + noun; lipgloss.Width(full) <= w {
		return full
	}
	if short := breadcrumbPrefix + path; lipgloss.Width(short) <= w {
		return short
	}
	return breadcrumbPrefix + truncateLeft(path, w-lipgloss.Width(breadcrumbPrefix))
}

// viewTable renders the column titles and as many rows as fit, keeping the
// cursor on screen.
func (m Model) viewTable() []string {
	cols := fitColumns(tableColumns(m.stack.Top().Mode, m.grouping, m.hostname), m.viewWidth())
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

// emptyBody explains a table with no rows in it. A filter and a drill-down
// scope are each a likelier reason for one than an idle capture, and each has
// its own way out, so all three are worded separately rather than any of them
// claiming the capture has seen nothing.
func (m Model) emptyBody() string {
	if m.filter != "" {
		return emptyFilterMessage
	}
	if m.stack.Depth() > 0 {
		return emptyScopeMessage
	}
	return emptyMessage
}

// viewHelp renders the full key reference in place of the table.
func (m Model) viewHelp() []string {
	h := m.help
	h.ShowAll = true
	h.Width = m.viewWidth()

	lines := []string{m.styles.ColumnHeader.Render("Key reference"), ""}
	lines = append(lines, strings.Split(h.FullHelpView(m.keys.FullHelp()), "\n")...)
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

// footerKeys picks the hints for the current context: the standard set at the
// top level, and once the user has drilled in, the way back out in place of
// the top-level mode toggle. Esc does nothing at depth 0 and tab does nothing
// below it, so advertising either where it has no effect would be a lie.
//
// A filter in force adds `/` to the list. It is the one state the user can put
// the table into that hides rows, so it is the one they may need to undo
// without having been told how; the rest of the time the footer is better
// spent on the keys that do something to what is on screen.
func (m Model) footerKeys() []key.Binding {
	keys := m.keys.ShortHelp()
	if m.stack.Depth() == 0 && m.filter == "" {
		return keys
	}

	out := make([]key.Binding, 0, len(keys)+1)
	for _, k := range keys {
		if m.stack.Depth() > 0 && k.Help() == m.keys.Mode.Help() {
			k = m.keys.Back
		}
		// Ahead of the help key, so the hints that change the table stay
		// together and the two that are about the session stay last.
		if m.filter != "" && k.Help() == m.keys.Help.Help() {
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
	n := m.rowLines()
	if n <= 0 {
		return lines
	}

	// rowLines counts data rows; the column-title line sits above them.
	n++
	for len(lines) < n {
		lines = append(lines, "")
	}
	return lines[:n]
}

// rowLines is how many table rows the terminal has room for, or 0 when its
// height is not known yet and every row is drawn.
func (m Model) rowLines() int {
	if m.height <= 0 {
		return 0
	}
	return max(m.height-chromeLines, 1)
}

// viewWidth is the terminal width, falling back to a sensible default until
// the first tea.WindowSizeMsg arrives.
func (m Model) viewWidth() int {
	if m.width <= 0 {
		return defaultWidth
	}
	return m.width
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

// modeLabel names the current view for the header bar. The by-destination
// grouping is part of the name because it changes what a row means, and there
// is no other affordance telling the user which of the two is active.
func modeLabel(mode Mode, g aggregate.Grouping) string {
	if mode == ModeProcess {
		return "By Process"
	}
	if g == aggregate.GroupByIPPort {
		return "By Destination (ip:port)"
	}
	return "By Destination (ip)"
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
