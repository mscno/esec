package projectfile

import (
	"strings"
	"testing"
)

func TestRunSettingsRoundtripAndRestrictions(t *testing.T) {
	raw := []byte("# preserve this comment\nproject='test/app'\n[run]\nenvironment_variable='APP_ENV'\n[env.dev.run]\npreserve_env=['DATABASE_URL']\n")
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := p.Env["dev"]
	e.Run.PreserveEnv = append(e.Run.PreserveEnv, "SERVER_PORT")
	p.Env["dev"] = e
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "# preserve this comment") || len(again.Env["dev"].Run.PreserveEnv) != 2 {
		t.Fatal(string(b))
	}
	for _, name := range []string{"prod", "production", "staging", "foo.prod"} {
		bad := strings.ReplaceAll(string(raw), "env.dev.run", "env."+name+".run")
		if name == "foo.prod" {
			bad = strings.ReplaceAll(string(raw), "env.dev.run", `env."foo.prod".run`)
		}
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted implicit override for %s", name)
		}
	}
	for _, name := range []string{"ESEC_AGE_IDENTITY", "LD_PRELOAD", "DYLD_LIBRARY_PATH", "PATH", "APP_ENV", "DATABASE_URL','DATABASE_URL"} {
		bad := strings.ReplaceAll(string(raw), "DATABASE_URL", name)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted unsafe override %s", name)
		}
	}
}
