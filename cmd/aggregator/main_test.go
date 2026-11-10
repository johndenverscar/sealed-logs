package main

import "testing"

// Search runs after decryption, so it can match through separators that would
// defeat any index built on ciphertext or tokens.
func TestMatches(t *testing.T) {
	for _, c := range []struct {
		msg, needle string
		want        bool
	}{
		{"charge failed for card 4111 1111 1111 1111", "4111", true},
		{"card 4-1-1-1", "4111", true},
		{"card 4🙂1🙂1🙂1", "4111 1", false},
		{"card 4🙂1🙂1🙂1", "4111", true},
		{"Payment FAILED", "failed", true},
		{"all good", "4111", false},
		{"anything", "", true},
	} {
		if got := matches(c.msg, c.needle); got != c.want {
			t.Errorf("matches(%q, %q) = %v, want %v", c.msg, c.needle, got, c.want)
		}
	}
}
