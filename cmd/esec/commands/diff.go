package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/mscno/esec"
	"github.com/mscno/esec/pkg/secretfile"
)

// DiffCmd compares public variable names; it never decrypts values.
type DiffCmd struct {
	Files    []string `arg:"" name:"environments" help:"Two or more environments or files"`
	KeysOnly bool     `default:"true" help:"Compare key names only; value comparison is not supported"`
	JSON     bool     `help:"Print the presence matrix as JSON"`
}
type keyDiff struct {
	Files []string     `json:"files"`
	Rows  []keyDiffRow `json:"rows"`
}
type keyDiffRow struct {
	Key     string `json:"key"`
	Present []bool `json:"present"`
}

// Run reports presence without treating an environment-specific key as an error.
func (c *DiffCmd) Run(_ *cliCtx) error {
	if !c.KeysOnly {
		return errors.New("only --keys-only comparison is supported; values are never decrypted")
	}
	diff, err := compareKeys(c.Files)
	if err != nil {
		return err
	}
	if c.JSON {
		return json.NewEncoder(os.Stdout).Encode(diff)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprint(w, "KEY")
	for _, f := range c.Files {
		fmt.Fprintf(w, "\t%q", f)
	}
	fmt.Fprintln(w)
	for _, row := range diff.Rows {
		fmt.Fprintf(w, "%q", row.Key)
		for _, present := range row.Present {
			if present {
				fmt.Fprint(w, "\tyes")
			} else {
				fmt.Fprint(w, "\t—")
			}
		}
		fmt.Fprintln(w)
	}
	return w.Flush()
}

func compareKeys(files []string) (*keyDiff, error) {
	if len(files) < 2 {
		return nil, errors.New("choose at least two environments or files")
	}
	out := &keyDiff{Files: []string{}, Rows: []keyDiffRow{}}
	columns := make([][]string, 0, len(files))
	all := map[string]bool{}
	for _, input := range files {
		t, err := esec.ResolveRead(".", input, "")
		if err != nil {
			return nil, errors.New("cannot resolve comparison file or its access metadata; use esec check")
		}
		if slices.Contains(out.Files, t.Path) {
			return nil, errors.New("the same file was selected more than once")
		}
		f, err := secretfile.Parse(t.Path, t.Content)
		if err != nil {
			return nil, errors.New("cannot parse comparison file; no values were displayed")
		}
		out.Files = append(out.Files, t.Path)
		columns = append(columns, f.Keys)
		for _, k := range f.Keys {
			all[k] = true
		}
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		row := keyDiffRow{Key: k, Present: make([]bool, len(columns))}
		for i, col := range columns {
			row.Present[i] = slices.Contains(col, k)
		}
		out.Rows = append(out.Rows, row)
	}
	return out, nil
}
