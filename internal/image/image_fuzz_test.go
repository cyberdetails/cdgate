package image

import (
	"bytes"
	"testing"
)

// FuzzOpen: an image archive is untrusted input; reading it must return an
// error, never panic or hang. In memory (OpenReader), so the fuzzer is fast.
func FuzzOpen(f *testing.F) {
	t := &testing.T{}
	f.Add(tarOf(t, []ent{{name: "manifest.json", body: `[{"Layers":["l"]}]`}, {name: "l", body: string(tarOf(t,
		[]ent{{name: "etc/debian_version", body: "12"}, {name: "var/lib/dpkg/status.d/.wh..wh..opq"}}))}}))
	f.Add([]byte("not a tar"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = OpenReader(bytes.NewReader(data), int64(len(data)))
	})
}
