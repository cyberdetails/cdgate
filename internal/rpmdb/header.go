package rpmdb

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// rpm header blob import, ported from go-rpmdb v0.1.1 entry.go (itself a port
// of rpm-4.14.3 lib/header.c: hdrblobInit, hdrblobVerifyRegion,
// hdrblobVerifyInfo, hdrblobImport, regionSwab). Arithmetic is 64-bit here, and
// the places where go-rpmdb would panic (slicing with a bad region index,
// a string without a terminator past the data end) return an error.

const (
	tagHeaderImage      = 61
	tagHeaderSignatures = 62
	tagHeaderImmutable  = 63
	tagI18NTable        = 100

	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagVendor          = 1011
	tagArch            = 1022
	tagSourceRpm       = 1044
	tagDirIndexes      = 1116
	tagBaseNames       = 1117
	tagDirNames        = 1118
	tagModularityLabel = 5096

	typeInt32       = 4
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
	typeMax         = 9

	regionTagCount = 16 // sizeof(entryInfo)
	headerMaxBytes = 256 * 1024 * 1024
)

var (
	typeSizes = [16]int64{0, 1, 1, 2, 4, 8, -1, 1, -1, -1}
	typeAlign = [16]int64{1, 1, 1, 2, 4, 8, 1, 1, 1, 1}
	errHeader = errors.New("malformed rpm header")
)

type entryInfo struct {
	tag    int64
	typ    uint32
	offset int64
	count  uint32
}

type indexEntry struct {
	info entryInfo
	data []byte
}

type hdrblob struct {
	pe                         []entryInfo
	il, dl, dataStart, dataEnd int64
	regionTag, ril, rdl        int64
}

func readEntry(b []byte) entryInfo { // on disk: network byte order (ei2h)
	return entryInfo{tag: int64(int32(be32(b))), typ: be32(b[4:]), offset: int64(int32(be32(b[8:]))), count: be32(b[12:])}
}

func headerImport(data []byte) ([]indexEntry, error) {
	b, err := hdrblobInit(data)
	if err != nil {
		return nil, err
	}
	return hdrblobImport(b, data)
}

func hdrblobInit(data []byte) (*hdrblob, error) {
	if len(data) < 8 {
		return nil, errHeader
	}
	b := &hdrblob{il: int64(int32(be32(data))), dl: int64(int32(be32(data[4:])))}
	if b.il < 1 {
		return nil, errors.New("region no tags error")
	}
	if b.dl < 0 || 8+16*b.il > int64(len(data)) {
		return nil, fmt.Errorf("%w: index length", errHeader)
	}
	b.dataStart = 8 + 16*b.il
	b.dataEnd = b.dataStart + b.dl
	if b.dataStart+b.dl >= headerMaxBytes {
		return nil, fmt.Errorf("%w: blob size", errHeader)
	}
	b.pe = make([]entryInfo, b.il)
	for i := range b.pe {
		b.pe[i] = readEntry(data[8+16*i:])
	}
	if err := verifyRegion(b, data); err != nil {
		return nil, err
	}
	if err := verifyInfo(b, data); err != nil {
		return nil, err
	}
	return b, nil
}

func outOfRange(dl, off int64) bool { return off < 0 || off > dl }

func verifyRegion(b *hdrblob, data []byte) error {
	e := b.pe[0]
	var regionTag int64
	if e.tag == tagHeaderImage || e.tag == tagHeaderSignatures || e.tag == tagHeaderImmutable {
		regionTag = e.tag
	}
	if e.tag != regionTag {
		return nil
	}
	if !(e.typ == typeBin && e.count == regionTagCount) {
		return errors.New("invalid region tag")
	}
	if outOfRange(b.dl, e.offset+regionTagCount) {
		return errors.New("invalid region offset")
	}
	regionEnd := b.dataStart + e.offset
	if regionEnd < 0 || regionEnd+regionTagCount > int64(len(data)) {
		return errors.New("invalid region offset")
	}
	trailer := readEntry(data[regionEnd:])
	b.rdl = regionEnd + regionTagCount - b.dataStart
	off := -trailer.offset
	b.ril = off / regionTagCount
	if off%regionTagCount != 0 || outOfRange(b.il, b.ril) || outOfRange(b.dl, b.rdl) {
		return fmt.Errorf("invalid region size, region %d", regionTag)
	}
	b.regionTag = regionTag
	return nil
}

func verifyInfo(b *hdrblob, data []byte) error {
	start := 0
	if b.regionTag != 0 {
		start = 1
	}
	for _, e := range b.pe[start:] {
		// go-rpmdb's "end > offset" check compares with a variable that is
		// always 0 (shadowed), so in effect it rejects a negative offset.
		switch {
		case e.offset < 0:
			return fmt.Errorf("%w: offset", errHeader)
		case e.tag < tagI18NTable:
			return fmt.Errorf("%w: tag", errHeader)
		case e.typ > typeMax:
			return fmt.Errorf("%w: type", errHeader)
		case e.offset&(typeAlign[e.typ]-1) != 0:
			return fmt.Errorf("%w: alignment", errHeader)
		case outOfRange(b.dl, e.offset):
			return fmt.Errorf("%w: range", errHeader)
		}
		n := dataLength(data, e.typ, e.count, b.dataStart+e.offset, b.dataEnd)
		if end := e.offset + n; outOfRange(b.dl, end) || n <= 0 {
			return fmt.Errorf("%w: data length", errHeader)
		}
	}
	return nil
}

func hdrblobImport(b *hdrblob, data []byte) ([]indexEntry, error) {
	var entries []indexEntry
	var rdlen int64
	var err error
	if b.pe[0].tag >= tagI18NTable { // an original v3 header
		entries, rdlen, err = regionSwab(data, b.pe, 0, b.dataStart, b.dataEnd)
		if err != nil {
			return nil, err
		}
	} else {
		ril := b.ril
		if b.pe[0].offset == 0 {
			ril = b.il
		}
		if ril < 1 || ril > int64(len(b.pe)) {
			return nil, fmt.Errorf("%w: region index", errHeader)
		}
		entries, rdlen, err = regionSwab(data, b.pe[1:ril], 0, b.dataStart, b.dataEnd)
		if err != nil {
			return nil, err
		}
		if rdlen < 0 {
			return nil, errors.New("invalid region length")
		}
		if b.ril < int64(len(b.pe)-1) {
			var dribble []indexEntry
			dribble, rdlen, err = regionSwab(data, b.pe[ril:], rdlen, b.dataStart, b.dataEnd)
			if err != nil {
				return nil, err
			}
			if rdlen < 0 {
				return nil, errors.New("invalid length of dribble entries")
			}
			// a dribble entry replaces a region entry with the same tag
			byTag := map[int64]int{}
			var merged []indexEntry
			for _, e := range append(entries, dribble...) {
				if i, ok := byTag[e.info.tag]; ok {
					merged[i] = e
					continue
				}
				byTag[e.info.tag] = len(merged)
				merged = append(merged, e)
			}
			entries = merged
		}
		rdlen += regionTagCount
	}
	if rdlen != b.dl {
		return nil, fmt.Errorf("the calculated length (%d) is different from the data length (%d)", rdlen, b.dl)
	}
	return entries, nil
}

func regionSwab(data []byte, pe []entryInfo, dl, dataStart, dataEnd int64) ([]indexEntry, int64, error) {
	out := make([]indexEntry, len(pe))
	for i, e := range pe {
		if e.typ > 15 {
			return nil, 0, fmt.Errorf("%w: type", errHeader)
		}
		start := dataStart + e.offset
		if start >= dataEnd {
			return nil, 0, errors.New("invalid data offset")
		}
		var n int64
		if i < len(pe)-1 && typeSizes[e.typ] == -1 {
			n = pe[i+1].offset - e.offset
		} else {
			n = dataLength(data, e.typ, e.count, start, dataEnd)
		}
		if n < 0 || start < 0 || start > int64(len(data)) || start+n > int64(len(data)) {
			return nil, 0, errors.New("invalid data length")
		}
		out[i] = indexEntry{info: e, data: data[start : start+n]}
		dl += n + alignDiff(e.typ, uint32(dl))
	}
	return out, dl, nil
}

func dataLength(data []byte, t, count uint32, start, dataEnd int64) int64 {
	switch t {
	case typeString:
		if count != 1 {
			return -1
		}
		return strtaglen(data, 1, start, dataEnd)
	case typeStringArray, typeI18NString:
		return strtaglen(data, count, start, dataEnd)
	}
	if t > 15 || typeSizes[t] == -1 {
		return -1
	}
	n := typeSizes[t] * int64(count)
	if n < 0 || dataEnd > 0 && start+n > dataEnd {
		return -1
	}
	return n
}

func alignDiff(t, size uint32) int64 {
	if ts := typeSizes[t]; ts > 1 {
		if d := ts - int64(size)%ts; d != ts {
			return d
		}
	}
	return 0
}

func strtaglen(data []byte, count uint32, start, dataEnd int64) int64 {
	if start < 0 || start >= dataEnd || dataEnd > int64(len(data)) {
		return -1
	}
	var n int64
	for c := count; c > 0; c-- {
		off := start + n
		if off > dataEnd {
			return -1
		}
		i := bytes.IndexByte(data[off:dataEnd], 0)
		if i < 0 {
			return -1 // unterminated string (go-rpmdb would miscount)
		}
		n += int64(i) + 1
	}
	return n
}

func str(e indexEntry) string { return string(bytes.TrimRight(e.data, "\x00")) }

func strs(e indexEntry) []string {
	return strings.Split(string(bytes.TrimRight(e.data, "\x00")), "\x00")
}

// packageInfo is go-rpmdb's getNEVRA for the tags used here, with the same
// type checks. Tags go-rpmdb also type-checks but the analysis never reads
// (PGP, file sizes, ...) are not looked at.
func packageInfo(ies []indexEntry) (Package, error) {
	var p Package
	var dirs, bases []string
	var idx []int32
	for _, e := range ies {
		want := uint32(typeString)
		switch e.info.tag {
		case tagDirIndexes, tagEpoch:
			want = typeInt32
		case tagDirNames, tagBaseNames:
			want = typeStringArray
		case tagName, tagVersion, tagRelease, tagArch, tagSourceRpm, tagVendor, tagModularityLabel:
		default:
			continue
		}
		if e.info.typ != want {
			return p, fmt.Errorf("invalid tag %d type %d", e.info.tag, e.info.typ)
		}
		switch e.info.tag {
		case tagName:
			p.Name = str(e)
		case tagVersion:
			p.Version = str(e)
		case tagRelease:
			p.Release = str(e)
		case tagArch:
			p.Arch = str(e)
		case tagModularityLabel:
			p.ModularityLabel = str(e)
		case tagSourceRpm:
			if p.SourceRpm = str(e); p.SourceRpm == "(none)" {
				p.SourceRpm = ""
			}
		case tagVendor:
			if p.Vendor = str(e); p.Vendor == "(none)" {
				p.Vendor = ""
			}
		case tagEpoch:
			if e.data != nil {
				if len(e.data) < 4 {
					return p, errors.New("failed to parse epoch")
				}
				p.Epoch = int(int32(be32(e.data)))
			}
		case tagDirNames:
			dirs = strs(e)
		case tagBaseNames:
			bases = strs(e)
		case tagDirIndexes:
			idx = make([]int32, len(e.data)/4)
			for i := range idx {
				idx[i] = int32(be32(e.data[4*i:]))
			}
		}
	}
	files, err := installedFiles(dirs, idx, bases)
	if err != nil {
		p.FilesInvalid = true
	}
	p.Files = files
	return p, nil
}
