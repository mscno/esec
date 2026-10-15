package keyringfile

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/joho/godotenv"

	"github.com/mscno/esec/pkg/secretstore"
)

const plainKeyring = "# ESEC_PROJECT=org/repo\nESEC_PRIVATE_KEY_DEV=24ab5041def8c84077bacce66524cc2ad37266ada17429e8e3c1db534dd2c2c5\n"

func testKey(b byte) *[32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return &k
}

func TestSealOpenRoundTrip(t *testing.T) {
	sealed, err := Seal([]byte(plainKeyring), testKey(1), "/x/org_repo.keyring")
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) {
		t.Fatal("sealed output not recognised")
	}
	if bytes.Contains(sealed, []byte("ESEC_PRIVATE_KEY")) {
		t.Fatal("sealed output leaks plaintext")
	}
	got, err := Open(sealed, testKey(1), "/other/dir/org_repo.keyring")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plainKeyring {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestOpenRejectsWrongKeyNameAndTampering(t *testing.T) {
	sealed, err := Seal([]byte(plainKeyring), testKey(1), "org_repo.keyring")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, testKey(2), "org_repo.keyring"); !errors.Is(err, ErrSealed) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if _, err := Open(sealed, testKey(1), "org_other.keyring"); !errors.Is(err, ErrSealed) {
		t.Fatalf("file swap accepted: %v", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(Magic)+5] ^= 0x01
	if _, err := Open(tampered, testKey(1), "org_repo.keyring"); err == nil {
		t.Fatal("tampered file accepted")
	}
	if _, err := Open([]byte(Magic+"\nAAAA\n"), testKey(1), "org_repo.keyring"); !errors.Is(err, ErrSealed) {
		t.Fatalf("truncated file accepted: %v", err)
	}
}

func TestIsSealed(t *testing.T) {
	for in, want := range map[string]bool{
		Magic + "\nabc\n":        true,
		Magic + "\r\nabc\r\n":    true,
		Magic:                    true,
		"# " + Magic + "\n":      false,
		"ESEC_PRIVATE_KEY=abc\n": false,
		"":                       false,
		"\n" + Magic + "\nabc\n": false,
		Magic + "X\nabc\n":       false,
	} {
		if got := IsSealed([]byte(in)); got != want {
			t.Errorf("IsSealed(%q) = %t, want %t", in, got, want)
		}
	}
}

// TestLegacyParserFailsLoudly pins the property that keeps old esec builds
// safe: the godotenv version they use rejects a sealed keyring outright, so an
// old esec reports a parse error instead of "key not found".
func TestLegacyParserFailsLoudly(t *testing.T) {
	sealed, err := Seal([]byte(plainKeyring), testKey(1), "org_repo.keyring")
	if err != nil {
		t.Fatal(err)
	}
	m, err := godotenv.Parse(bytes.NewReader(sealed))
	if err == nil {
		t.Fatalf("godotenv parsed a sealed keyring without error: %v", m)
	}
	if !strings.Contains(err.Error(), "unexpected character") {
		t.Fatalf("unexpected godotenv error: %v", err)
	}
}

func TestCodecUsesStore(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	store := secretstore.NewMemory()
	c := Codec{Store: store}
	if _, err := c.Decode("org_repo.keyring", []byte(Magic+"\nAAAA\n")); !errors.Is(err, ErrCacheKey) {
		t.Fatalf("missing cache key not reported: %v", err)
	}
	out, err := c.Encode("org_repo.keyring", []byte(plainKeyring), true)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := c.Parse("org_repo.keyring", out)
	if err != nil {
		t.Fatal(err)
	}
	if entries["ESEC_PRIVATE_KEY_DEV"] == "" {
		t.Fatal("entry missing after sealed round trip")
	}
	plain, err := c.Encode("org_repo.keyring", []byte(plainKeyring), false)
	if err != nil || string(plain) != plainKeyring {
		t.Fatal("plain encode must not change content")
	}
	k1, err := EnsureCacheKey(store)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := EnsureCacheKey(store)
	if err != nil || *k1 != *k2 {
		t.Fatal("cache key not stable")
	}
	if err := store.Set(CacheKeyName, "not-hex"); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCacheKey(store); err == nil {
		t.Fatal("malformed cache key silently replaced")
	}
}

func TestEnsureCacheKeyConcurrent(t *testing.T) {
	t.Setenv("ESEC_VAULT_HOME", t.TempDir())
	store := secretstore.NewMemory()
	keys := make(chan [32]byte, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			k, err := EnsureCacheKey(store)
			if err != nil {
				t.Error(err)
				return
			}
			keys <- *k
		})
	}
	wg.Wait()
	close(keys)
	first := <-keys
	for k := range keys {
		if k != first {
			t.Fatal("concurrent creators produced different cache keys")
		}
	}
}
