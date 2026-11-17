//go:build ignore

package main

import (
	"fmt"
	"os"
	"sort"
	"unicode/utf8"
)

func main() {
	entity, entity2 := entityMaps()
	type e struct {
		k    string
		a, b rune
	}
	var all []e
	for k, v := range entity {
		all = append(all, e{k, v, 0})
	}
	for k, v := range entity2 {
		if _, dup := entity[k]; dup {
			panic("dup " + k)
		}
		all = append(all, e{k, v[0], v[1]})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].k < all[j].k })
	w := os.Stdout
	fmt.Fprintln(w, "// Generated from Go's src/html/entity.go (go1.26.10) by the bytetext generator; do not edit.")
	fmt.Fprintf(w, "pub const LONGEST_UNTERMINATED_ENTITY: usize = %d;\n\n", longestEntityWithoutSemicolon)
	fmt.Fprintln(w, "/// (name without '&', first rune, second rune or 0), sorted by name bytes.")
	fmt.Fprintf(w, "pub static ENTITIES: [(&[u8], u32, u32); %d] = [\n", len(all))
	for _, x := range all {
		n := utf8.RuneLen(x.a)
		if x.b != 0 {
			n += utf8.RuneLen(x.b)
		}
		if n > 1+len(x.k) {
			panic("entity longer than its name: " + x.k)
		}
		fmt.Fprintf(w, "    (b%q, 0x%X, 0x%X),\n", x.k, x.a, x.b)
	}
	fmt.Fprintln(w, "];")
}
