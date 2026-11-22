package langpkg

// Rust executables built with cargo-auditable carry their dependency list in a
// zlib-compressed JSON section. Trivy (00b7394, pkg/dependency/parser/rust/
// binary) reads it with github.com/rust-secure-code/go-rustaudit
// (e20ec32e963c, MIT); this is the same reading on the standard library:
//
//	ELF     .dep-v0, else .rust-deps-v0
//	PE      .dep-v0, else rdep-v0
//	Mach-O  .dep-v0, else rust-deps-v0 (thin files only; a universal file
//	        does not open with macho.NewFile and yields nothing, as in Trivy)
//	wasm    custom section .dep-v0
//
// Only "runtime" packages are reported (a missing kind means runtime), the
// root crate included, as crates.io packages.
//
// Untrusted input (Trivy has no caps): the decompressed JSON is capped, wasm
// section sizes must fit in the file, and a panic in a stdlib parser means
// "not readable".

import (
	"bytes"
	"compress/zlib"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const maxRustDepJSON = 16 << 20

var (
	errNotRust      = errors.New("no Rust dependency information")
	errUnknownExe   = errors.New("unknown executable format")
	wasmHeader      = []byte("\x00asm\x01\x00\x00\x00")
	rustDepSection  = ".dep-v0"
	machoHeaderBE   = []byte("\xFE\xED\xFA")
	machoHeaderLE   = []byte("\xFA\xED\xFE")
	machoUniversal  = []byte("\xCA\xFE\xBA\xBE")
	rustElfLegacy   = ".rust-deps-v0"
	rustPELegacy    = "rdep-v0"
	rustMachoLegacy = "rust-deps-v0"
)

// RustExeCandidate: the formats go-rustaudit opens (first 16 bytes).
func RustExeCandidate(ident []byte) bool {
	if len(ident) < 16 {
		return false
	}
	return bytes.HasPrefix(ident, []byte("\x7FELF")) || bytes.HasPrefix(ident, []byte("MZ")) ||
		bytes.HasPrefix(ident, machoHeaderBE) || bytes.HasPrefix(ident[1:], machoHeaderLE) ||
		bytes.HasPrefix(ident, machoUniversal) || bytes.HasPrefix(ident, wasmHeader)
}

// RustBinary is what one executable yields: packages, or Err when it carries
// the section but it does not read (Trivy: the file fails, nothing reported).
type RustBinary struct {
	Packages [][2]string
	Err      string
}

type rustDepPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// ReadRustBinary returns nil for anything that is not a cargo-auditable
// executable.
func ReadRustBinary(b []byte) (rb *RustBinary) {
	defer func() {
		if recover() != nil {
			rb = &RustBinary{Err: "executable could not be parsed"}
		}
	}()
	data, err := rustDepSectionData(b)
	if errors.Is(err, errNotRust) || errors.Is(err, errUnknownExe) {
		return nil
	} else if err != nil {
		return &RustBinary{Err: err.Error()}
	}
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return &RustBinary{Err: "section not compressed"}
	}
	defer zr.Close()
	js, err := io.ReadAll(io.LimitReader(zr, maxRustDepJSON+1))
	if err != nil {
		return &RustBinary{Err: "failed to decompress JSON"}
	}
	if len(js) > maxRustDepJSON {
		return &RustBinary{Err: "dependency information too large"}
	}
	var info struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(js, &info); err != nil {
		return &RustBinary{Err: "failed to unmarshal JSON"}
	}
	res := &RustBinary{}
	for _, raw := range info.Packages {
		p := rustDepPackage{Kind: "runtime"} // go-rustaudit's default
		if err := json.Unmarshal(raw, &p); err != nil {
			return &RustBinary{Err: "failed to unmarshal JSON"}
		}
		if p.Kind != "runtime" {
			continue
		}
		res.Packages = append(res.Packages, [2]string{p.Name, p.Version})
	}
	return res
}

func rustDepSectionData(b []byte) ([]byte, error) {
	if len(b) < 16 {
		return nil, errUnknownExe
	}
	r := bytes.NewReader(b)
	switch {
	case bytes.HasPrefix(b, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, errUnknownExe
		}
		s := f.Section(rustDepSection)
		if s == nil {
			s = f.Section(rustElfLegacy)
		}
		if s == nil {
			return nil, errNotRust
		}
		return s.Data()
	case bytes.HasPrefix(b, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return nil, errUnknownExe
		}
		s := f.Section(rustDepSection)
		if s == nil {
			s = f.Section(rustPELegacy)
		}
		if s == nil {
			return nil, errNotRust
		}
		return s.Data()
	case bytes.HasPrefix(b, machoHeaderBE) || bytes.HasPrefix(b[1:], machoHeaderLE) || bytes.HasPrefix(b, machoUniversal):
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, errUnknownExe
		}
		s := f.Section(rustDepSection)
		if s == nil {
			s = f.Section(rustMachoLegacy)
		}
		if s == nil {
			return nil, errNotRust
		}
		return s.Data()
	case bytes.HasPrefix(b, wasmHeader):
		return wasmDepSection(b)
	}
	return nil, errUnknownExe
}

// wasmDepSection walks wasm sections exactly as go-rustaudit's ReadAt loop
// does: every length is decoded from a 4-byte read (a read past the end, even
// of zero bytes, is an error), so a 5-byte LEB128 length is rejected too.
func wasmDepSection(b []byte) ([]byte, error) {
	read := func(off, n int) ([]byte, bool) {
		if off >= len(b) || n > len(b)-off {
			return nil, false
		}
		return b[off : off+n], true
	}
	u32 := func(off int) (int, int, bool) {
		buf, ok := read(off, 4)
		if !ok {
			return 0, 0, false
		}
		v, n := binary.Uvarint(buf)
		if n <= 0 || v > uint64(^uint32(0)) {
			return 0, 0, false
		}
		return int(v), n, true
	}
	off := len(wasmHeader)
	for {
		if off >= len(b) {
			return nil, errNotRust // EOF looking for the next section
		}
		id := b[off]
		off++
		size, n, ok := u32(off)
		if !ok {
			return nil, errUnknownExe
		}
		off += n
		next := off + size
		if id != 0 {
			off = next
			continue
		}
		nameSize, n, ok := u32(off)
		if !ok {
			return nil, errUnknownExe
		}
		off += n
		name, ok := read(off, nameSize)
		if !ok {
			return nil, errUnknownExe
		}
		off += nameSize
		if string(name) != rustDepSection {
			off = next
			continue
		}
		if next < off {
			return nil, errUnknownExe // go-rustaudit panics on the negative make
		}
		data, ok := read(off, next-off)
		if !ok {
			return nil, errUnknownExe
		}
		return data, nil
	}
}
