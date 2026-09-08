package tui

import (
	"strings"
	"testing"
)

// hasBoldSGR reports whether any SGR escape sequence in s carries the bold
// code (1). sgrCodes only inspects the first sequence in a string, which for
// a rendered panel title bar is the border's own color code rather than the
// title's — this walks every sequence instead.
func hasBoldSGR(s string) bool {
	for _, seq := range ansiPattern.FindAllString(s, -1) {
		body := strings.TrimSuffix(strings.TrimPrefix(seq, "\x1b["), "m")
		for _, code := range strings.Split(body, ";") {
			if code == "1" {
				return true
			}
		}
	}
	return false
}

func TestRenderPanelTitleBarFocusVsBlurred(t *testing.T) {
	withANSI(t)
	styles := DefaultStyles()

	focused := renderPanelTitleBar(styles, "Test", 20, true)
	blurred := renderPanelTitleBar(styles, "Test", 20, false)

	if focused == blurred {
		t.Fatalf("a focused and unfocused title bar rendered identically")
	}

	// PanelTitle is bold, PanelTitleBlurred is not: this is the one attribute
	// that survives stripping colour down to the SGR codes the ANSI profile
	// still emits.
	if !hasBoldSGR(focused) {
		t.Errorf("focused title bar is missing the bold SGR code, got %q", focused)
	}
	if hasBoldSGR(blurred) {
		t.Errorf("blurred title bar should not be bold, got %q", blurred)
	}
}

func TestRenderPanelUnchangedWhenFocused(t *testing.T) {
	withANSI(t)
	styles := DefaultStyles()

	// The focused path is what every panel rendered before focus/zoom
	// existed, so it must still carry PanelTitle's bold attribute.
	got := renderPanelTitleBar(styles, "Connections", 30, true)
	if !hasBoldSGR(got) {
		t.Errorf("focused panel title lost its bold attribute, got %q", got)
	}
}

func TestRenderPanelBorderDiffersByFocus(t *testing.T) {
	withANSI(t)
	styles := DefaultStyles()

	focused := renderPanel(styles, "Test", 20, 5, "body", true)
	blurred := renderPanel(styles, "Test", 20, 5, "body", false)

	if focused == blurred {
		t.Errorf("a focused and unfocused panel rendered identically")
	}
}
