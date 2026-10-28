package projectfile

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// edit rewrites raw (which decodes to orig) so it decodes to want, changing
// only the lines of values that differ and keeping comments and layout. It
// reports false when the result does not decode to want, such as for a file
// written with inline tables or dotted keys.
func edit(raw []byte, orig, want *File) ([]byte, bool) {
	d := doc{lines: strings.SplitAfter(string(raw), "\n")}
	if d.lines[len(d.lines)-1] == "" {
		d.lines = d.lines[:len(d.lines)-1]
	}
	if want.Project != orig.Project {
		d.set("", "project", want.Project)
	}
	if want.Files.Format != orig.Files.Format {
		d.set("files", "format", want.Files.Format)
	}
	if want.Files.Name != orig.Files.Name {
		d.set("files", "name", want.Files.Name)
	}
	names := map[string]bool{}
	for n := range orig.Env {
		names[n] = true
	}
	for n := range want.Env {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		o, w := orig.Env[n], want.Env[n]
		table := "env." + tomlKey(n)
		if w.Key != o.Key {
			d.set(table, "key", w.Key)
		}
		if w.Guard != o.Guard {
			d.set(table, "guard", w.Guard)
		}
		if !slices.Equal(w.Readers, o.Readers) {
			d.setRaw(table, "readers", tomlStrings(w.Readers))
		}
	}
	out := []byte(strings.Join(d.lines, ""))
	got, err := Parse(out)
	if err != nil || !got.same(want) {
		return nil, false
	}
	return out, true
}

// doc is a TOML file as lines, each with its newline.
type doc struct{ lines []string }

var (
	headerLine = regexp.MustCompile(`^\s*\[([^\[\]]+)\]\s*(#.*)?$`)
	keyLine    = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=`)
	bareKey    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// table returns the range of lines of table (the root for ""): from its
// header (or the file's start) to the next header. found is false when the
// file has no such table.
func (d *doc) table(name string) (start, end int, found bool) {
	start, end = 0, len(d.lines)
	in := name == ""
	found = in
	for i, l := range d.lines {
		m := headerLine.FindStringSubmatch(strings.TrimRight(l, "\r\n"))
		if m == nil {
			continue
		}
		if in {
			return start, i, true
		}
		if normalizeTable(m[1]) == name {
			in, found, start = true, true, i+1
		}
	}
	return start, end, found
}

func normalizeTable(s string) string {
	parts := strings.Split(s, ".")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if u, err := strconv.Unquote(p); err == nil {
			p = tomlKey(u)
		}
		parts[i] = p
	}
	return strings.Join(parts, ".")
}

// tomlKey writes a key bare when it can be, else quoted.
func tomlKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return strconv.Quote(k)
}

// tomlStrings writes a list of strings as a one-line TOML array, "" for an
// empty one (which set then removes).
func tomlStrings(list []string) string {
	if len(list) == 0 {
		return ""
	}
	quoted := make([]string, len(list))
	for i, v := range list {
		quoted[i] = strconv.Quote(v)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// set sets key in table to the string value, or removes it for "".
func (d *doc) set(table, key, value string) {
	if value == "" {
		d.setRaw(table, key, "")
		return
	}
	d.setRaw(table, key, strconv.Quote(value))
}

// setRaw sets key in table to a TOML value written out, or removes it for
// "". It adds the table at the end when there is none.
func (d *doc) setRaw(table, key, value string) {
	start, end, found := d.table(table)
	line := key + " = " + value + "\n"
	for i := start; found && i < end; i++ {
		m := keyLine.FindStringSubmatch(d.lines[i])
		if m == nil || m[1] != key {
			continue
		}
		if value == "" {
			d.lines = append(d.lines[:i], d.lines[i+1:]...)
			return
		}
		// Keep a trailing comment.
		if c := trailingComment(d.lines[i]); c != "" {
			line = strings.TrimSuffix(line, "\n") + " " + c + "\n"
		}
		d.lines[i] = line
		return
	}
	if value == "" {
		return
	}
	if !found {
		d.appendTable(table, line)
		return
	}
	d.insert(start, end, table == "", line)
}

// appendTable adds a table with one line at the end of the file.
func (d *doc) appendTable(table, line string) {
	if n := len(d.lines); n > 0 && !strings.HasSuffix(d.lines[n-1], "\n") {
		d.lines[n-1] += "\n"
	}
	if n := len(d.lines); n > 0 && strings.TrimSpace(d.lines[n-1]) != "" {
		d.lines = append(d.lines, "\n")
	}
	d.lines = append(d.lines, "["+table+"]\n", line)
}

// insert adds line to the table at lines start:end, after its last key and
// before its trailing blank lines and comments (which usually introduce the
// next table).
func (d *doc) insert(start, end int, root bool, line string) {
	at := start
	for i := start; i < end; i++ {
		if keyLine.MatchString(d.lines[i]) {
			at = i + 1
		}
	}
	if root && at == 0 {
		// A root key goes after the leading comment.
		for at < end && strings.HasPrefix(strings.TrimSpace(d.lines[at]), "#") {
			at++
		}
	}
	if at > 0 && !strings.HasSuffix(d.lines[at-1], "\n") {
		d.lines[at-1] += "\n"
	}
	d.lines = append(d.lines[:at], append([]string{line}, d.lines[at:]...)...)
}

// trailingComment returns the "# …" after a simple quoted value, if any.
func trailingComment(l string) string {
	l = strings.TrimRight(l, "\r\n")
	eq := strings.Index(l, "=")
	rest := strings.TrimSpace(l[eq+1:])
	if len(rest) < 2 || (rest[0] != '"' && rest[0] != '\'') {
		return ""
	}
	end := strings.IndexByte(rest[1:], rest[0])
	if end < 0 {
		return ""
	}
	after := strings.TrimSpace(rest[end+2:])
	if strings.HasPrefix(after, "#") {
		return after
	}
	return ""
}
