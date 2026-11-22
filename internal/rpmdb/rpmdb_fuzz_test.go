package rpmdb

import "testing"

// FuzzParse: an rpm database inside an image is untrusted; Parse must return
// (an error or packages), never panic or hang. Seeds are the real fixtures.
func FuzzParse(f *testing.F) {
	for _, n := range []string{"bdb.db.gz", "c5.db.gz", "ndb.db.gz", "sqlite.db.gz", "sqlite512.db.gz", "reserved.db.gz"} {
		f.Add(fixture(f, n))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Parse(b)
		if len(b) > 8 {
			_, _ = headerImport(b[8:])
		}
	})
}
