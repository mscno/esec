package blob

import (
	"bytes"
	"strings"
	"testing"
)

func TestExactRoundTrip(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("key\r\n\n"), {0, 255, 128, 1}, bytes.Repeat([]byte{255}, MaxSize)} {
		value, err := Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(value)
		if err != nil || !bytes.Equal(decoded, data) {
			t.Fatal("exact round trip failed", err)
		}
	}
	if _, err := Encode(make([]byte, MaxSize+1)); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestRejectMalformedVersionEncodingAndSize(t *testing.T) {
	for _, value := range []string{"secret-do-not-print", "esec-blob-v2:AA==", prefix + "AB==", prefix + "AA==\n", prefix + "AA", prefix + "!", prefix + strings.Repeat("A", 4*((MaxSize+3)/3))} {
		if _, err := Decode(value); err == nil || strings.Contains(err.Error(), "secret-do-not-print") {
			t.Fatal("invalid blob accepted or error exposed its value")
		}
	}
}
