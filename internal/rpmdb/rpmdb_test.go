package rpmdb

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// The fixtures were written by rpm itself, in the distribution's own
// container: "rpm --initdb" then "rpm -i --justdb" of two small packages
// (amazonlinux:2 → Berkeley DB, opensuse/leap:15.6 → NDB, rockylinux:9 →
// SQLite). The .expected and .files files are that rpm's own
// "rpm -qa --qf ..." and "rpm -qal" output. sqlite512 is the SQLite fixture's
// rows copied 20 times by Python's sqlite3 into a database with 512-byte
// pages, so that interior B-tree pages and overflow chains are exercised.

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(g)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func line(p Package) string {
	src, ven := p.SourceRpm, p.Vendor
	if src == "" {
		src = "(none)"
	}
	if ven == "" {
		ven = "(none)"
	}
	return fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s", p.Name, p.Epoch, p.Version, p.Release, p.Arch, src, ven)
}

func TestAgainstRPM(t *testing.T) {
	for _, f := range []string{"bdb", "ndb", "sqlite"} {
		pk, err := Parse(fixture(t, f+".db.gz"))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var got, files []string
		for _, p := range pk {
			got = append(got, line(p))
			if p.FilesInvalid {
				t.Errorf("%s %s: file list invalid", f, p.Name)
			}
			files = append(files, p.Files...)
		}
		sort.Strings(got)
		sort.Strings(files)
		want, _ := os.ReadFile("testdata/" + f + ".expected")
		if strings.Join(got, "\n") != strings.TrimSpace(string(want)) {
			t.Errorf("%s packages\n got %s\nwant %s", f, strings.Join(got, "\n"), want)
		}
		wantFiles, _ := os.ReadFile("testdata/" + f + ".files")
		if strings.Join(files, "\n") != strings.TrimSpace(string(wantFiles)) {
			t.Errorf("%s: %d files, rpm -qal lists %d", f, len(files), strings.Count(string(wantFiles), "\n"))
		}
	}
}

func TestSQLiteInteriorPagesAndOverflow(t *testing.T) {
	b := fixture(t, "sqlite512.db.gz")
	if be16(b[16:]) != 512 {
		t.Fatal("fixture is not a 512-byte page database")
	}
	pk, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 40 {
		t.Fatalf("%d packages", len(pk))
	}
	// rowid order (checked with Python's sqlite3: hnum 1 is words, rpm's
	// install order); the 40 copies alternate words, tree
	for i, p := range pk {
		if want := []string{"words", "tree"}[i%2]; p.Name != want {
			t.Fatalf("row %d: %s, want %s", i, p.Name, want)
		}
	}
}

func TestEVRAndSourceRpm(t *testing.T) {
	for _, c := range []struct {
		p    Package
		want string
	}{
		{Package{Version: "1.0", Release: "1.el9"}, "1.0-1.el9"},
		{Package{Version: "1.0", Release: "1.el9", Epoch: 2}, "2:1.0-1.el9"},
		{Package{Version: "3.0"}, "3.0"},
	} {
		if got := c.p.EVR(); got != c.want {
			t.Errorf("EVR %q, want %q", got, c.want)
		}
	}
	n, v, r, err := SplitSourceRpm("tree-pkg-1.8.0-10.el9.src.rpm")
	if err != nil || n != "tree-pkg" || v != "1.8.0" || r != "10.el9" {
		t.Errorf("%q %q %q %v", n, v, r, err)
	}
	for _, bad := range []string{"nodots", "a.rpm", "x-1.src.rpm"} {
		if _, _, _, err := SplitSourceRpm(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// must return within a second: the malformed inputs below would hang or
// panic a reader that trusts page numbers.
func mustFail(t *testing.T, name string, b []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		_, err := Parse(b)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("%s: expected an error", name)
		} else if strings.HasPrefix(err.Error(), "panic") {
			t.Errorf("%s: %v", name, err)
		}
	case <-time.After(time.Second):
		t.Errorf("%s: did not return", name)
	}
}

func TestMalformed(t *testing.T) {
	sq := fixture(t, "sqlite512.db.gz")
	// root page of sqlite_schema made interior with its right child = itself
	loop := append([]byte(nil), sq...)
	loop[100] = 0x05
	binary.BigEndian.PutUint16(loop[103:], 0)
	binary.BigEndian.PutUint32(loop[108:], 1)
	mustFail(t, "sqlite page loop", loop)
	mustFail(t, "sqlite truncated", sq[:600])
	bad := append([]byte(nil), sq...)
	binary.BigEndian.PutUint16(bad[16:], 1000) // not a power of two
	mustFail(t, "sqlite page size", bad)

	bdb := fixture(t, "bdb.db.gz")
	ps := int(binary.LittleEndian.Uint32(bdb[20:]))
	// point every overflow chain at the metadata page (go-rpmdb loops forever)
	chain := append([]byte(nil), bdb...)
	found := false
	for pg := 0; pg*ps < len(chain); pg++ {
		p := chain[pg*ps : (pg+1)*ps]
		if p[25] != bdbHashPage {
			continue
		}
		n := int(binary.LittleEndian.Uint16(p[20:]))
		for i := 1; i < n; i += 2 {
			idx := int(binary.LittleEndian.Uint16(p[bdbPageHeaderSize+2*i:]))
			if p[idx] == bdbHOffPage {
				binary.LittleEndian.PutUint32(p[idx+4:], 0)
				binary.LittleEndian.PutUint32(p[idx+4:], uint32(pg)) // a hash page, not an overflow page
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no off-page item in the BDB fixture")
	}
	mustFail(t, "bdb chain to a non-overflow page", chain)
	mustFail(t, "bdb truncated", bdb[:len(bdb)/2])

	ndb := fixture(t, "ndb.db.gz")
	slot := append([]byte(nil), ndb...)
	copy(slot[32:], "XXXX")
	mustFail(t, "ndb bad slot magic", slot)
	huge := append([]byte(nil), ndb...)
	binary.LittleEndian.PutUint32(huge[12:], 4096)
	mustFail(t, "ndb slot page limit", huge)

	mustFail(t, "header garbage", append([]byte("SQLite format 3\x00"), bytes.Repeat([]byte{0xff}, 2000)...))
	if _, err := headerImport([]byte{0, 0, 0, 0x7f, 0, 0, 0, 1}); err == nil {
		t.Error("header with an index larger than the blob must fail")
	}
}

func TestMoreFormats(t *testing.T) {
	// CentOS 5 (rpm 4.4.2.3, Berkeley DB 4.3): unsorted hash pages (type 2);
	// c5.expected is that rpm's own query output.
	c5 := fixture(t, "c5.db.gz")
	pk, err := Parse(c5)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pk {
		got = append(got, line(p))
	}
	sort.Strings(got)
	want, _ := os.ReadFile("testdata/c5.expected")
	if strings.Join(got, "\n") != strings.TrimSpace(string(want)) {
		t.Errorf("c5: %v", got)
	}
	// written by the sqlite3 shell (.filectrl reserve_bytes 37) and by Python
	// with page_size=65536 (stored as 1 in the header)
	for _, f := range []string{"reserved.db.gz", "sqlite64k.db.gz"} {
		b := fixture(t, f)
		pk, err := Parse(b)
		if err != nil || len(pk) != 30 {
			t.Fatalf("%s: %d packages, %v", f, len(pk), err)
		}
		for i, p := range pk {
			if want := []string{"words", "tree"}[i%2]; p.Name != want {
				t.Fatalf("%s row %d: %s", f, i, p.Name)
			}
		}
	}
}

// bigEndian rewrites the little-endian BDB fixture in big-endian byte order,
// swapping the fields libdb stores in host order and this reader uses (page
// header, hash index, off-page item); rpm header blobs are byte-order free.
// No big-endian machine was available to write a real one.
func bigEndian(t *testing.T, b []byte) []byte {
	out := append([]byte(nil), b...)
	ps := int(binary.LittleEndian.Uint32(b[20:]))
	sw32 := func(p []byte, off int) { binary.BigEndian.PutUint32(p[off:], binary.LittleEndian.Uint32(p[off:])) }
	sw16 := func(p []byte, off int) { binary.BigEndian.PutUint16(p[off:], binary.LittleEndian.Uint16(p[off:])) }
	for off := 8; off < 96; off += 4 {
		if off != 24 { // bytes 24..27: algorithm, type, flags, unused
			sw32(out, off)
		}
	}
	for pg := 1; (pg+1)*ps <= len(out); pg++ {
		src, dst := b[pg*ps:(pg+1)*ps], out[pg*ps:(pg+1)*ps]
		n := int(binary.LittleEndian.Uint16(src[20:]))
		sw32(dst, 8)
		sw32(dst, 12)
		sw32(dst, 16)
		sw16(dst, 20)
		sw16(dst, 22)
		if src[25] == bdbHashPage || src[25] == bdbHashUnsorted {
			for i := 0; i < n; i++ {
				idx := int(binary.LittleEndian.Uint16(src[bdbPageHeaderSize+2*i:]))
				sw16(dst, bdbPageHeaderSize+2*i)
				if i%2 == 1 && src[idx] == bdbHOffPage {
					sw32(dst, idx+4)
					sw32(dst, idx+8)
				}
			}
		}
	}
	return out
}

func TestBDBByteOrderAndLength(t *testing.T) {
	le := fixture(t, "bdb.db.gz")
	be := bigEndian(t, le)
	if binary.BigEndian.Uint32(be[12:]) != bdbHashMagic {
		t.Fatal("conversion did not produce a big-endian magic")
	}
	a, err1 := Parse(le)
	b, err2 := Parse(be)
	if err1 != nil || err2 != nil || len(a) != 2 || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("LE %v %v\nBE %v %v", a, err1, b, err2)
	}
	// each value is exactly the off-page item's length (hf_offset on the last page)
	blobs, err := bdbBlobs(le)
	if err != nil {
		t.Fatal(err)
	}
	ps := int(binary.LittleEndian.Uint32(le[20:]))
	var lengths []int
	for pg := 1; (pg+1)*ps <= len(le); pg++ {
		p := le[pg*ps : (pg+1)*ps]
		if p[25] != bdbHashPage {
			continue
		}
		for i := 1; i < int(binary.LittleEndian.Uint16(p[20:])); i += 2 {
			idx := int(binary.LittleEndian.Uint16(p[bdbPageHeaderSize+2*i:]))
			if p[idx] == bdbHOffPage {
				lengths = append(lengths, int(binary.LittleEndian.Uint32(p[idx+8:])))
			}
		}
	}
	if len(lengths) != len(blobs) {
		t.Fatalf("%d values, %d off-page items", len(blobs), len(lengths))
	}
	for i := range blobs {
		if len(blobs[i]) != lengths[i] {
			t.Errorf("value %d: %d bytes, item length %d", i, len(blobs[i]), lengths[i])
		}
	}
}

func TestMalformedDetails(t *testing.T) {
	bdb := fixture(t, "bdb.db.gz")
	ps := int(binary.LittleEndian.Uint32(bdb[20:]))
	chain := append([]byte(nil), bdb...)
	for pg := 1; (pg+1)*ps <= len(chain); pg++ {
		p := chain[pg*ps : (pg+1)*ps]
		if p[25] != bdbHashPage {
			continue
		}
		for i := 1; i < int(binary.LittleEndian.Uint16(p[20:])); i += 2 {
			idx := int(binary.LittleEndian.Uint16(p[bdbPageHeaderSize+2*i:]))
			if p[idx] == bdbHOffPage {
				binary.LittleEndian.PutUint32(p[idx+4:], uint32(pg))
			}
		}
	}
	if _, err := Parse(chain); err == nil || !strings.Contains(err.Error(), "not an overflow page") {
		t.Errorf("chain into a hash page: %v", err)
	}

	ndb := fixture(t, "ndb.db.gz")
	for i := 0; 32+16*i+16 <= len(ndb); i++ {
		s := ndb[32+16*i:]
		if le32(s) == ndbSlotMagic && le32(s[4:]) != 0 {
			off := int(le32(s[8:])) * ndbBlobHeaderSize
			bad := append([]byte(nil), ndb...)
			binary.LittleEndian.PutUint32(bad[off+4:], le32(s[4:])+1000)
			if _, err := Parse(bad); err == nil || !strings.Contains(err.Error(), "failed to find NDB blob") {
				t.Errorf("blob of another package: %v", err)
			}
			break
		}
	}

	// two interior cells pointing at the same subtree: rows would be read twice
	sq := fixture(t, "sqlite512.db.gz")
	dup := append([]byte(nil), sq...)
	done := false
	for pg := 2; pg*512 <= len(dup) && !done; pg++ {
		p := dup[(pg-1)*512 : pg*512]
		if p[0] != 0x05 || be16(p[3:]) == 0 {
			continue
		}
		cell := int(be16(p[12:]))
		copy(p[cell:cell+4], p[8:12]) // first child := right-most child
		done = true
	}
	if !done {
		t.Fatal("no interior page in the 512-byte fixture")
	}
	if _, err := Parse(dup); err == nil {
		t.Error("a subtree reached twice must be an error")
	}

	blob := func() []byte {
		bl, err := sqliteBlobs(fixture(t, "sqlite.db.gz"))
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), bl[0]...)
	}
	if _, err := headerImport(blob()); err != nil {
		t.Fatalf("unmodified blob: %v", err)
	}
	// data length declared 16 bytes longer than the entries account for
	longer := append(blob(), make([]byte, 16)...)
	binary.BigEndian.PutUint32(longer[4:], be32(longer[4:])+16)
	if _, err := headerImport(longer); err == nil || !strings.Contains(err.Error(), "calculated length") {
		t.Errorf("dl mismatch: %v", err)
	}
	// a data entry with a tag below HEADER_I18NTABLE (100)
	lowTag := blob()
	binary.BigEndian.PutUint32(lowTag[8+16:], 50)
	if _, err := headerImport(lowTag); err == nil {
		t.Error("tag below 100 must be rejected")
	}
}

func TestVarintAndRecord(t *testing.T) {
	v, n, ok := varint([]byte{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff})
	if !ok || n != 9 || v != 1<<57|0xff {
		t.Errorf("9-byte varint: %x %d %v", v, n, ok)
	}
	if v, n, ok := varint([]byte{0x7f}); !ok || v != 0x7f || n != 1 {
		t.Error("1-byte varint")
	}
	// header: size 3, types 5 (6-byte int) and 19 (3-byte text)
	rec, types, err := record([]byte{3, 5, 19, 0, 0, 0, 0, 1, 2, 'a', 'b', 'c'})
	if err != nil || len(rec) != 2 || len(rec[0]) != 6 || string(rec[1]) != "abc" || types[0] != 5 {
		t.Errorf("%v %v %v", rec, types, err)
	}
	if x, ok := intValue([]byte{0xff, 0xfe}, 2); !ok || x != -2 {
		t.Errorf("sign extension: %d", x)
	}
}

func TestPackageInfoTags(t *testing.T) {
	s := func(tag int64, v string) indexEntry {
		return indexEntry{info: entryInfo{tag: tag, typ: typeString}, data: []byte(v + "\x00")}
	}
	arr := func(tag int64, v ...string) indexEntry {
		return indexEntry{info: entryInfo{tag: tag, typ: typeStringArray}, data: []byte(strings.Join(v, "\x00") + "\x00")}
	}
	i32 := func(tag int64, v ...int32) indexEntry {
		b := make([]byte, 4*len(v))
		for i, x := range v {
			binary.BigEndian.PutUint32(b[4*i:], uint32(x))
		}
		return indexEntry{info: entryInfo{tag: tag, typ: typeInt32}, data: b}
	}
	p, err := packageInfo([]indexEntry{s(tagName, "x"), s(tagSourceRpm, "(none)"), s(tagVendor, "(none)"),
		i32(tagEpoch, 300), arr(tagDirNames, "/usr/bin/", "/etc/"), arr(tagBaseNames, "a", "b"), i32(tagDirIndexes, 0, 1)})
	if err != nil || p.SourceRpm != "" || p.Vendor != "" || p.Epoch != 300 ||
		strings.Join(p.Files, ",") != "/usr/bin/a,/etc/b" || p.FilesInvalid {
		t.Errorf("%+v %v", p, err)
	}
	p, err = packageInfo([]indexEntry{s(tagName, "x"), arr(tagDirNames, "/a/"), arr(tagBaseNames, "x", "y"), i32(tagDirIndexes, 0)})
	if err != nil || !p.FilesInvalid {
		t.Errorf("index/name count mismatch must mark the file list invalid: %+v", p)
	}
	if _, err := installedFiles([]string{"/a/", "/b/", "/c/"}, []int32{0, 1}, []string{"x", "y"}); err == nil {
		t.Error("more directories than names must be invalid")
	}
	if _, err := packageInfo([]indexEntry{{info: entryInfo{tag: tagName, typ: typeInt32}, data: []byte{0, 0, 0, 1}}}); err == nil {
		t.Error("a name tag with the wrong type must fail")
	}
}
