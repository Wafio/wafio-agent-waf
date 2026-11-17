//go:build ignore

package main

import (
	"fmt"
	"os"
	"unicode"
)

func ranges(pred func(rune) bool) [][2]rune {
	var out [][2]rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !pred(r) {
			continue
		}
		if n := len(out); n > 0 && out[n-1][1] == r-1 {
			out[n-1][1] = r
		} else {
			out = append(out, [2]rune{r, r})
		}
	}
	return out
}

func emitRanges(name string, pred func(rune) bool) {
	rs := ranges(pred)
	fmt.Printf("pub static %s: [(u32, u32); %d] = [", name, len(rs))
	for i, r := range rs {
		if i%6 == 0 {
			fmt.Print("\n   ")
		}
		fmt.Printf(" (0x%X, 0x%X),", r[0], r[1])
	}
	fmt.Println("\n];")
}

func emitMap(name string, f func(rune) rune) {
	var ps [][2]rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if m := f(r); m != r {
			ps = append(ps, [2]rune{r, m})
		}
	}
	fmt.Printf("pub static %s: [(u32, u32); %d] = [", name, len(ps))
	for i, p := range ps {
		if i%6 == 0 {
			fmt.Print("\n   ")
		}
		fmt.Printf(" (0x%X, 0x%X),", p[0], p[1])
	}
	fmt.Println("\n];")
}

func in(t *unicode.RangeTable) func(rune) bool { return func(r rune) bool { return unicode.Is(t, r) } }

func main() {
	fmt.Fprintln(os.Stdout, "// Generated from Go's unicode package (go1.26.10, Unicode "+unicode.Version+") by the bytetext generator; do not edit.")
	fmt.Println("#![allow(clippy::all)]")
	fmt.Printf("pub const UNICODE_VERSION: &str = %q;\n", unicode.Version)
	emitRanges("IS_LETTER", unicode.IsLetter)
	emitRanges("IS_UPPER", unicode.IsUpper)
	emitRanges("IS_LOWER", unicode.IsLower)
	emitRanges("IS_DIGIT", unicode.IsDigit)
	emitRanges("IS_NUMBER", unicode.IsNumber)
	emitRanges("IS_MARK", unicode.IsMark)
	emitRanges("IS_PUNCT", unicode.IsPunct)
	emitRanges("IS_SYMBOL", unicode.IsSymbol)
	emitRanges("IS_SPACE", unicode.IsSpace)
	emitRanges("IS_CONTROL", unicode.IsControl)
	emitRanges("IS_PRINT", unicode.IsPrint)
	emitRanges("IS_GRAPHIC", unicode.IsGraphic)
	emitRanges("CAT_CC", in(unicode.Cc))
	emitRanges("CAT_CF", in(unicode.Cf))
	emitRanges("CAT_CO", in(unicode.Co))
	emitRanges("CAT_CS", in(unicode.Cs))
	emitRanges("CAT_MN", in(unicode.Mn))
	emitRanges("CAT_MC", in(unicode.Mc))
	emitRanges("CAT_ME", in(unicode.Me))
	emitRanges("CAT_ND", in(unicode.Nd))
	emitRanges("CAT_Z", in(unicode.Z))
	emitRanges("CAT_ZS", in(unicode.Zs))
	emitMap("TO_LOWER", unicode.ToLower)
	emitMap("TO_UPPER", unicode.ToUpper)
	emitMap("SIMPLE_FOLD", unicode.SimpleFold)
}
