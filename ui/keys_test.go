package ui

import (
	"strings"
	"testing"
)

func TestFullHelpDocumentsEveryBinding(t *testing.T) {
	keys := DefaultKeyMap()

	documented := make(map[string]bool)
	for _, column := range keys.FullHelp() {
		for _, b := range column {
			documented[b.Help().Key] = true
		}
	}

	// The `?` overlay is the only place several of these keys are ever
	// mentioned, so a binding missing from it is a key the user has no way to
	// discover.
	for _, b := range allBindings(t, keys) {
		if !documented[b.Help().Key] {
			t.Errorf("binding %q (%s) is not in the help overlay", b.Help().Key, b.Help().Desc)
		}
	}
}

func TestShortHelpIsPartOfTheFullReference(t *testing.T) {
	keys := DefaultKeyMap()

	full := make(map[string]bool)
	for _, column := range keys.FullHelp() {
		for _, b := range column {
			full[b.Help().Key] = true
		}
	}

	// The footer is a shortlist of the reference, not a second list: a hint
	// that appears only there would be one the overlay contradicts.
	for _, b := range keys.ShortHelp() {
		if !full[b.Help().Key] {
			t.Errorf("footer hint %q is missing from the full reference", b.Help().Key)
		}
	}
}

func TestBindingsDoNotShareAKey(t *testing.T) {
	owner := make(map[string]string)

	// Update matches bindings in order, so two of them claiming the same key
	// would leave one silently unreachable — `g` and `G` being one typo apart
	// is exactly how that happens.
	for _, b := range allBindings(t, DefaultKeyMap()) {
		for _, k := range b.Keys() {
			if prev, ok := owner[k]; ok {
				t.Errorf("key %q is bound to both %q and %q", k, prev, b.Help().Desc)
			}
			owner[k] = b.Help().Desc
		}
	}
}

func TestKeyHelpIsFilledIn(t *testing.T) {
	for _, b := range allBindings(t, DefaultKeyMap()) {
		h := b.Help()
		if strings.TrimSpace(h.Key) == "" || strings.TrimSpace(h.Desc) == "" {
			t.Errorf("binding %v has incomplete help text %+v", b.Keys(), h)
		}
	}
}
