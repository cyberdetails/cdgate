package rpmdb

import (
	"errors"
	"fmt"
	"strings"
)

// A read-only reader for exactly what rpm's SQLite backend needs: the
// "blob" column of every row of table "Packages", in rowid order (what
// "SELECT blob FROM Packages" returns for a table scan). File format:
// https://www.sqlite.org/fileformat2.html — database header, table B-trees
// (interior 0x05, leaf 0x0D), cell payload with overflow pages, record format.
//
// Only the main database file is read. A -wal file is ignored, as in Trivy,
// which copies the main file alone to a temporary path before opening it.

const (
	maxSQLitePages = 4 << 20
	maxBTreeDepth  = 32
)

var errSQLite = errors.New("malformed SQLite database")

type sqliteDB struct {
	b        []byte
	pageSize int
	usable   int
	pages    int
}

func (db *sqliteDB) page(n uint32) ([]byte, error) {
	if n < 1 || int(n) > db.pages {
		return nil, fmt.Errorf("%w: page %d out of range", errSQLite, n)
	}
	off := (int(n) - 1) * db.pageSize
	return db.b[off : off+db.pageSize], nil
}

// varint: big-endian base-128, at most 9 bytes, the 9th contributing 8 bits.
func varint(b []byte) (uint64, int, bool) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0, false
		}
		if i == 8 {
			return v<<8 | uint64(b[i]), 9, true
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
	}
	return 0, 0, false
}

func sqliteBlobs(b []byte) ([][]byte, error) {
	if len(b) < 100 {
		return nil, errSQLite
	}
	ps := int(be16(b[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", errSQLite, ps)
	}
	if enc := be32(b[56:]); enc != 0 && enc != 1 {
		return nil, fmt.Errorf("SQLite text encoding %d is not supported", enc)
	}
	reserved := int(b[20])
	db := &sqliteDB{b: b, pageSize: ps, usable: ps - reserved, pages: len(b) / ps}
	if db.usable < 480 || db.pages < 1 || db.pages > maxSQLitePages {
		return nil, errSQLite
	}
	// sqlite_schema: type, name, tbl_name, rootpage, sql
	var root uint32
	var sql string
	err := db.scan(1, 0, map[uint32]bool{}, func(rec [][]byte, types []uint64) error {
		if len(rec) < 5 || !isText(types[0]) || !isText(types[1]) {
			return nil
		}
		if string(rec[0]) == "table" && strings.EqualFold(string(rec[1]), "Packages") {
			r, ok := intValue(rec[3], types[3])
			if !ok || r < 1 || r > int64(db.pages) {
				return fmt.Errorf("%w: Packages root page", errSQLite)
			}
			root = uint32(r)
			if isText(types[4]) {
				sql = string(rec[4])
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if root == 0 {
		return nil, errors.New("SQLite database has no Packages table")
	}
	col, err := blobColumn(sql)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	err = db.scan(root, 0, map[uint32]bool{}, func(rec [][]byte, types []uint64) error {
		if col >= len(rec) || !(isBlob(types[col]) || isText(types[col])) {
			return fmt.Errorf("%w: Packages row without a blob", errSQLite)
		}
		out = append(out, rec[col])
		return nil
	})
	return out, err
}

// blobColumn finds "blob" in rpm's schema,
// CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL).
func blobColumn(sql string) (int, error) {
	i, j := strings.IndexByte(sql, '('), strings.LastIndexByte(sql, ')')
	if i < 0 || j < i {
		return 0, fmt.Errorf("unexpected Packages schema")
	}
	for n, def := range strings.Split(sql[i+1:j], ",") {
		f := strings.Fields(def)
		if len(f) > 0 && strings.EqualFold(strings.Trim(f[0], "'\"`[]"), "blob") {
			return n, nil
		}
	}
	return 0, fmt.Errorf("unexpected Packages schema: no blob column")
}

func isText(t uint64) bool { return t >= 13 && t%2 == 1 }
func isBlob(t uint64) bool { return t >= 12 && t%2 == 0 }

func intValue(v []byte, t uint64) (int64, bool) {
	switch t {
	case 8:
		return 0, true
	case 9:
		return 1, true
	case 1, 2, 3, 4, 5, 6:
		var x int64
		for _, c := range v {
			x = x<<8 | int64(c)
		}
		n := uint(len(v) * 8)
		return x << (64 - n) >> (64 - n), true // sign-extend
	}
	return 0, false
}

func serialLen(t uint64) (int, bool) {
	switch {
	case t <= 4:
		return []int{0, 1, 2, 3, 4}[t], true
	case t == 5:
		return 6, true
	case t == 6, t == 7:
		return 8, true
	case t == 8, t == 9:
		return 0, true
	case t == 10, t == 11:
		return 0, false
	case t > 2*MaxBlob+13:
		return 0, false
	}
	return int((t - 12) / 2), true
}

// scan walks a table B-tree in key order and calls fn with each record.
func (db *sqliteDB) scan(pg uint32, depth int, seen map[uint32]bool, fn func([][]byte, []uint64) error) error {
	if depth > maxBTreeDepth || seen[pg] {
		return fmt.Errorf("%w: B-tree loop", errSQLite)
	}
	seen[pg] = true
	p, err := db.page(pg)
	if err != nil {
		return err
	}
	hdr := 0
	if pg == 1 {
		hdr = 100
	}
	if hdr+8 > len(p) {
		return errSQLite
	}
	kind := p[hdr]
	n := int(be16(p[hdr+3:]))
	ptrs := hdr + 8
	if kind == 0x05 {
		ptrs = hdr + 12
	}
	if ptrs+2*n > db.usable {
		return errSQLite
	}
	cell := func(i int) (int, error) {
		off := int(be16(p[ptrs+2*i:]))
		if off < ptrs+2*n || off >= db.usable {
			return 0, errSQLite
		}
		return off, nil
	}
	switch kind {
	case 0x05:
		for i := 0; i < n; i++ {
			off, err := cell(i)
			if err != nil {
				return err
			}
			if off+4 > db.usable {
				return errSQLite
			}
			if err := db.scan(be32(p[off:]), depth+1, seen, fn); err != nil {
				return err
			}
		}
		return db.scan(be32(p[hdr+8:]), depth+1, seen, fn)
	case 0x0d:
		for i := 0; i < n; i++ {
			off, err := cell(i)
			if err != nil {
				return err
			}
			payload, err := db.payload(p, off)
			if err != nil {
				return err
			}
			rec, types, err := record(payload)
			if err != nil {
				return err
			}
			if err := fn(rec, types); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%w: page %d is not a table B-tree page (type %#x)", errSQLite, pg, kind)
}

// payload assembles a leaf cell's payload, following overflow pages.
func (db *sqliteDB) payload(p []byte, off int) ([]byte, error) {
	size, n1, ok := varint(p[off:db.usable])
	if !ok || size > MaxBlob+1024 {
		return nil, errSQLite
	}
	_, n2, ok := varint(p[off+n1 : db.usable])
	if !ok {
		return nil, errSQLite
	}
	start := off + n1 + n2
	u := db.usable
	P := int(size)
	x := u - 35
	local := P
	if P > x {
		m := ((u-12)*32)/255 - 23
		k := m + (P-m)%(u-4)
		local = m
		if k <= x {
			local = k
		}
	}
	if start+local > u {
		return nil, errSQLite
	}
	out := make([]byte, 0, P)
	out = append(out, p[start:start+local]...)
	if local == P {
		return out, nil
	}
	if start+local+4 > u {
		return nil, errSQLite
	}
	next := be32(p[start+local:])
	seen := map[uint32]bool{}
	for len(out) < P {
		if next == 0 || seen[next] {
			return nil, fmt.Errorf("%w: overflow chain", errSQLite)
		}
		seen[next] = true
		op, err := db.page(next)
		if err != nil {
			return nil, err
		}
		take := u - 4
		if rest := P - len(out); rest < take {
			take = rest
		}
		out = append(out, op[4:4+take]...)
		next = be32(op)
	}
	return out, nil
}

// record splits a record into column values and serial types.
func record(b []byte) ([][]byte, []uint64, error) {
	hl, n, ok := varint(b)
	if !ok || int(hl) > len(b) || int(hl) < n {
		return nil, nil, errSQLite
	}
	var types []uint64
	for i := n; i < int(hl); {
		t, k, ok := varint(b[i:hl])
		if !ok {
			return nil, nil, errSQLite
		}
		types = append(types, t)
		i += k
	}
	vals := make([][]byte, len(types))
	pos := int(hl)
	for i, t := range types {
		l, ok := serialLen(t)
		if !ok || pos+l > len(b) {
			return nil, nil, errSQLite
		}
		vals[i] = b[pos : pos+l]
		pos += l
	}
	return vals, types, nil
}
