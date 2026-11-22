package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Berkeley DB hash database (rpm < 4.16), go-rpmdb pkg/bdb: every hash page's
// value entries that point to an off-page item (HOFFPAGE) are followed
// through their overflow pages; nothing else carries package headers.

const (
	bdbHashMagic       = 0x00061561
	bdbHashMagicBE     = 0x61150600
	bdbHashMetaPage    = 8
	bdbHashUnsorted    = 2  // pre-4.6 hash pages (RHEL/CentOS 5)
	bdbHashPage        = 13 // sorted hash page
	bdbOverflowPage    = 7
	bdbHOffPage        = 3
	bdbPageHeaderSize  = 26
	bdbHOffPageSize    = 12
	bdbMaxValuesPerRun = 1 << 20
)

var errBDB = errors.New("malformed Berkeley DB database")

func bdbBlobs(b []byte) ([][]byte, error) {
	if len(b) < 512 {
		return nil, errBDB
	}
	order := binary.ByteOrder(binary.LittleEndian)
	magic := order.Uint32(b[12:])
	if magic == bdbHashMagicBE {
		order = binary.BigEndian
		magic = order.Uint32(b[12:])
	}
	if magic != bdbHashMagic {
		return nil, fmt.Errorf("unexpected DB magic number: %#x", magic)
	}
	if b[24] != 0 {
		return nil, fmt.Errorf("unexpected encryption algorithm: %d", b[24])
	}
	if b[25] != bdbHashMetaPage {
		return nil, fmt.Errorf("unexpected page type: %d", b[25])
	}
	ps := order.Uint32(b[20:])
	switch ps {
	case 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536:
	default:
		return nil, fmt.Errorf("unexpected page size: %d", ps)
	}
	last := order.Uint32(b[32:])
	pageSize := int(ps)
	pages := len(b) / pageSize
	page := func(n uint32) ([]byte, error) {
		if int64(n) >= int64(pages) {
			return nil, fmt.Errorf("%w: page %d out of range", errBDB, n)
		}
		return b[int(n)*pageSize : (int(n)+1)*pageSize], nil
	}
	var out [][]byte
	for pn := uint32(0); pn <= last; pn++ {
		pg, err := page(pn)
		if err != nil {
			return nil, err
		}
		if t := pg[25]; t != bdbHashUnsorted && t != bdbHashPage {
			continue
		}
		entries := int(order.Uint16(pg[20:]))
		if entries%2 != 0 {
			return nil, fmt.Errorf("invalid hash index: entries should only come in pairs (%d)", entries)
		}
		if bdbPageHeaderSize+2*entries > pageSize {
			return nil, errBDB
		}
		// every second 2-byte index entry (the values; keys are skipped)
		for i := 1; i < entries; i += 2 {
			idx := int(order.Uint16(pg[bdbPageHeaderSize+2*i:]))
			if idx >= pageSize {
				return nil, errBDB
			}
			if pg[idx] != bdbHOffPage {
				continue
			}
			if idx+bdbHOffPageSize > pageSize {
				return nil, errBDB
			}
			v, err := bdbValue(page, order, order.Uint32(pg[idx+4:]), last)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	}
	return out, nil
}

// bdbValue concatenates an overflow chain. go-rpmdb loops forever when a
// chain page is not an overflow page; that is an error here.
func bdbValue(page func(uint32) ([]byte, error), order binary.ByteOrder, first, last uint32) ([]byte, error) {
	var v []byte
	seen := map[uint32]bool{}
	for cur := first; cur != 0; {
		if seen[cur] || cur > last {
			return nil, fmt.Errorf("%w: overflow chain", errBDB)
		}
		seen[cur] = true
		pg, err := page(cur)
		if err != nil {
			return nil, err
		}
		if pg[25] != bdbOverflowPage {
			return nil, fmt.Errorf("%w: page %d in an overflow chain is not an overflow page", errBDB, cur)
		}
		next := order.Uint32(pg[16:])
		if next == 0 {
			n := int(order.Uint16(pg[22:])) // hf_offset: bytes used on the last page
			if bdbPageHeaderSize+n > len(pg) {
				return nil, errBDB
			}
			v = append(v, pg[bdbPageHeaderSize:bdbPageHeaderSize+n]...)
		} else {
			v = append(v, pg[bdbPageHeaderSize:]...)
		}
		if len(v) > MaxBlob {
			return nil, fmt.Errorf("package header larger than %d MiB", MaxBlob>>20)
		}
		cur = next
	}
	return v, nil
}
