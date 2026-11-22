package rpmdb

import (
	"errors"
	"fmt"
)

// NDB (rpm's "new database", SUSE), go-rpmdb pkg/ndb: a 32-byte header, then
// SlotNPages 4 KiB pages of 16-byte slots (the first two slots are the header
// itself); each used slot points to a blob header + rpm header blob.

const (
	ndbHeaderMagic    = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic      = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobMagic      = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
	ndbSlotsPerPage   = 4096 / 16
	ndbMaxSlotPages   = 2048
	ndbBlobHeaderSize = 16
)

var errNDB = errors.New("malformed NDB database")

func ndbBlobs(b []byte) ([][]byte, error) {
	if len(b) < 32 {
		return nil, errNDB
	}
	if le32(b[4:]) != 0 { // NDBVersion
		return nil, errNDB
	}
	npages := le32(b[12:])
	if npages == 0 {
		return nil, errNDB
	}
	if npages > ndbMaxSlotPages {
		return nil, fmt.Errorf("slot page limit exceeded: %x", npages)
	}
	nslots := int(npages)*ndbSlotsPerPage - 2
	if 32+16*nslots > len(b) {
		return nil, fmt.Errorf("%w: slot pages truncated", errNDB)
	}
	var out [][]byte
	for i := 0; i < nslots; i++ {
		s := b[32+16*i:]
		if le32(s) != ndbSlotMagic {
			return nil, fmt.Errorf("bad slot Magic: %x", le32(s))
		}
		pkg := le32(s[4:])
		if pkg == 0 {
			continue
		}
		off := int64(le32(s[8:])) * ndbBlobHeaderSize
		if off+ndbBlobHeaderSize > int64(len(b)) {
			return nil, fmt.Errorf("%w: blob offset", errNDB)
		}
		h := b[off:]
		if le32(h) != ndbBlobMagic {
			return nil, fmt.Errorf("unexpected NDB blob Magic for pkg %d", pkg)
		}
		if le32(h[4:]) != pkg {
			return nil, fmt.Errorf("failed to find NDB blob for pkg %d", pkg)
		}
		n := int64(le32(h[12:]))
		if n > MaxBlob || off+ndbBlobHeaderSize+n > int64(len(b)) {
			return nil, fmt.Errorf("%w: blob length", errNDB)
		}
		out = append(out, b[off+ndbBlobHeaderSize:off+ndbBlobHeaderSize+n])
	}
	return out, nil
}
