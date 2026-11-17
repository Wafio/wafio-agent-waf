//go:build ignore

// Checks the model bytetext/norm.rs relies on: every x/text NFKC/NFKD/NFC/NFD lookup unit that
// is not a valid UTF-8 encoding of a Unicode-15-assigned scalar has no normalization data
// (zero properties: ccc 0, no decomposition, boundary before and after), and the unit size
// rule (truncated lead = size 0). Prints violations and a summary.
package main

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func isCont(b byte) bool { return b >= 0x80 && b < 0xC0 }

// model size: 0 = truncated
func modelSize(s []byte) int {
	c0 := s[0]
	switch {
	case c0 < 0x80:
		return 1
	case c0 < 0xC2:
		return 1
	}
	need := 0
	switch {
	case c0 < 0xE0:
		need = 2
	case c0 < 0xF0:
		need = 3
	case c0 < 0xF8:
		need = 4
	default:
		return 1
	}
	if len(s) < need {
		return 0
	}
	for k := 1; k < need; k++ {
		if !isCont(s[k]) {
			return k
		}
	}
	return need
}

func assigned(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs)
}

func main() {
	forms := []norm.Form{norm.NFC, norm.NFD, norm.NFKC, norm.NFKD}
	bad, checked := 0, 0
	check := func(b []byte) {
		for _, f := range forms {
			p := f.Properties(b)
			if modelSize(b) == 0 && p.Size() == 1 {
				continue // truncated lead: x/text reports size 1 + isInvalid (copies the rest)
			}
			if p.Size() != modelSize(b) {
				if bad < 20 {
					fmt.Printf("size %x: go %d model %d\n", b, p.Size(), modelSize(b))
				}
				bad++
			}
			n := p.Size()
			if n == 0 {
				continue
			}
			r, w := utf8.DecodeRune(b[:n])
			real := (w == n && r != utf8.RuneError) || (n == 1 && b[0] < 0x80) || (w == 3 && r == utf8.RuneError && n == 3 && b[0] == 0xEF)
			if real && (b[0] < 0x80 || assigned(r)) {
				continue
			}
			if p.CCC() != 0 || len(p.Decomposition()) != 0 || !p.BoundaryBefore() || !p.BoundaryAfter() {
				if bad < 20 {
					fmt.Printf("data %x (form %v): ccc %d dec %x\n", b[:n], f, p.CCC(), p.Decomposition())
				}
				bad++
			}
			checked++
		}
	}
	for c0 := 0x80; c0 < 0x100; c0++ {
		check([]byte{byte(c0)})
		for c1 := 0; c1 < 0x100; c1++ {
			check([]byte{byte(c0), byte(c1)})
			if c0 >= 0xE0 && c0 < 0xF8 && isCont(byte(c1)) {
				for c2 := 0; c2 < 0x100; c2++ {
					check([]byte{byte(c0), byte(c1), byte(c2)})
					if c0 >= 0xF0 && isCont(byte(c2)) {
						for c3 := 0; c3 < 0x100; c3++ {
							check([]byte{byte(c0), byte(c1), byte(c2), byte(c3)})
						}
					}
				}
			}
		}
	}
	// every scalar: unassigned in Unicode 15 has no data
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if (r >= 0xD800 && r <= 0xDFFF) || assigned(r) {
			continue
		}
		b := []byte(string(r))
		for _, f := range forms {
			p := f.Properties(b)
			if p.CCC() != 0 || len(p.Decomposition()) != 0 || !p.BoundaryBefore() || !p.BoundaryAfter() {
				if bad < 40 {
					fmt.Printf("unassigned %U has data (form %v)\n", r, f)
				}
				bad++
			}
		}
	}
	fmt.Printf("checked %d units, %d violations\n", checked, bad)
}
