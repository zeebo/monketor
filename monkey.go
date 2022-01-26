package monketor

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/zeebo/errs/v2"
	"golang.org/x/arch/x86/x86asm"
)

type fnInfo struct {
	name string
	lpc  uint64
	hpc  uint64
	buf  []byte
	ord  int
}

type patch struct {
	src fnInfo
	dst fnInfo

	lpc uint64
	hpc uint64
	buf []byte
}

var (
	ctrBase   uintptr
	ordOffset uint64
	tabOffset uint64
)

func trampoline()

var call = false

func init() {
	if call {
		trampoline()
	}
}

var globalCounters struct {
	on  sync.Once
	c   *Counters
	err error
}

type Counters struct {
	counters []uint32
	byName   map[string]fnInfo
	byPC     map[uint64]fnInfo
}

func (c *Counters) Iterate(cb func(name string, count uint32)) {
	for name, fi := range c.byName {
		cb(name, atomic.LoadUint32(&c.counters[fi.ord]))
	}
}

func (c *Counters) Calls(name string) uint32 {
	fi, ok := c.byName[name]
	if !ok {
		return 0
	}
	return atomic.LoadUint32(&c.counters[fi.ord])
}

func MonkeyAround() (*Counters, error) {
	globalCounters.on.Do(func() {
		globalCounters.c, globalCounters.err = monkeyAround()
	})
	return globalCounters.c, globalCounters.err
}

func monkeyAround() (*Counters, error) {
	c := &Counters{
		byName: make(map[string]fnInfo),
		byPC:   make(map[uint64]fnInfo),
	}

	path, err := os.Executable()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	fh, err := os.Open(path)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	defer fh.Close()

	efh, err := elf.Open(path)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	defer efh.Close()

	data, err := efh.DWARF()
	if err != nil {
		return nil, errs.Wrap(err)
	}

	var minpc, maxpc uint64

	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, errs.Wrap(err)
		}

		if entry == nil {
			break
		}

		if entry.Tag != dwarf.TagSubprogram {
			continue
		}

		name, ok := entry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		lpc, ok := entry.Val(dwarf.AttrLowpc).(uint64)
		if !ok {
			continue
		}
		hpc, ok := entry.Val(dwarf.AttrHighpc).(uint64)
		if !ok {
			continue
		}

		if minpc == 0 || lpc < minpc {
			minpc = lpc
		}
		if hpc > maxpc {
			maxpc = hpc
		}

		info := fnInfo{
			name: name,
			lpc:  lpc,
			hpc:  hpc,
			buf:  slice(lpc, hpc),
			ord:  len(c.byName),
		}

		for {
			if _, ok := c.byName[info.name]; ok {
				name += "'"
			}
			break
		}

		c.byName[info.name] = info
		c.byPC[info.lpc] = info
	}

	trampInfo, ok := c.byName["monketor.trampoline"]
	if !ok {
		return nil, errs.Errorf("cannot find monketor.trampoline")
	}

	var patches []patch

	for _, src := range c.byName {
		if !applyPatch(src.name) {
			continue
		}

		buf, lpc := src.buf, src.lpc

		for len(buf) > 0 {
			inst, err := x86asm.Decode(buf, 64)
			if err != nil {
				buf = buf[1:]
				lpc++
				continue
			}

			if inst.Op == x86asm.CALL && inst.Len == 5 {
				_, ok := inst.Args[0].(x86asm.Rel)
				if ok {
					hpc := lpc + uint64(inst.Len)
					rel := binary.LittleEndian.Uint32(buf[1:5])
					dpc := uint64(rel + uint32(hpc))
					if dst, ok := c.byPC[dpc]; ok && applyPatch(dst.name) {
						patches = append(patches, patch{
							src: src,
							dst: dst,
							lpc: lpc,
							hpc: hpc,
						})
					}
				}
			}

			buf = buf[inst.Len:]
			lpc += uint64(inst.Len)
		}
	}

	if len(patches) == 0 {
		return nil, err
	}

	sort.Slice(patches, func(i, j int) bool {
		return patches[i].lpc < patches[j].lpc
	})

	pageSize := uint64(syscall.Getpagesize())
	pageMask := ^(pageSize - 1)

	tabAllocSize := patches[len(patches)-1].lpc - patches[0].lpc
	tabNumPages := (tabAllocSize + pageSize - 1) / pageSize
	tabAlignedSize := tabNumPages * pageSize

	ctrAllocSize := uint64(len(c.byPC) * 4)
	ctrNumPages := (ctrAllocSize + pageSize - 1) / pageSize
	ctrAlignedSize := ctrNumPages * pageSize

	fmt.Println("page size:            ", pageSize)
	fmt.Println("table alloc size:     ", tabAllocSize)
	fmt.Println("table num pages:      ", tabNumPages)
	fmt.Println("table aligned size:   ", float64(tabAlignedSize)/1024/1024, "MiB")
	fmt.Println("ctr alloc size:       ", ctrAllocSize)
	fmt.Println("ctr num pages:        ", ctrNumPages)
	fmt.Println("ctr aligned size:     ", float64(ctrAlignedSize)/1024/1024, "MiB")

	if uint64(int(tabAlignedSize)) != tabAlignedSize {
		return nil, errs.Errorf("table aligned size too large")
	}

	if uint64(int(ctrAlignedSize)) != ctrAlignedSize {
		return nil, errs.Errorf("ctr aligned size too large")
	}

	tabBase, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		uintptr(0),
		uintptr(tabAlignedSize),
		uintptr(syscall.PROT_READ|syscall.PROT_WRITE),
		uintptr(syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS),
		^uintptr(0),
		uintptr(0),
	)
	if errno != 0 {
		return nil, errs.Wrap(errno)
	}
	tabOffset = uint64(tabBase) - patches[0].hpc

	ordBase, _, errno := syscall.Syscall6(
		syscall.SYS_MMAP,
		uintptr(0),
		uintptr(tabAlignedSize),
		uintptr(syscall.PROT_READ|syscall.PROT_WRITE),
		uintptr(syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS),
		^uintptr(0),
		uintptr(0),
	)
	if errno != 0 {
		return nil, errs.Wrap(errno)
	}
	ordOffset = uint64(ordBase) - patches[0].hpc

	ctrBase, _, errno = syscall.Syscall6(
		syscall.SYS_MMAP,
		uintptr(0),
		uintptr(ctrAlignedSize),
		uintptr(syscall.PROT_READ|syscall.PROT_WRITE),
		uintptr(syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS),
		^uintptr(0),
		uintptr(0),
	)

	{
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&c.counters))
		hdr.Data = ctrBase
		hdr.Cap = len(c.byPC)
		hdr.Len = len(c.byPC)
	}

	fmt.Printf("table mapping:         [0x%08x, 0x%08x]\n", tabBase, tabBase+uintptr(tabAlignedSize))
	fmt.Printf("table offset:          %016x\n", tabOffset)
	fmt.Printf("ord mapping:           [0x%08x, 0x%08x]\n", ordBase, ordBase+uintptr(tabAlignedSize))
	fmt.Printf("ord offset:            %016x\n", ordOffset)

	lpc := minpc & pageMask
	hpc := (maxpc + pageSize - 1) & pageMask

	if err := syscall.Mprotect(slice(lpc, hpc), allProt); err != nil {
		return nil, errs.Wrap(err)
	}

	for _, patch := range patches {
		tab := tabOffset + patch.hpc
		binary.LittleEndian.PutUint32(slice(tab, tab+4), uint32(patch.dst.lpc))

		ord := ordOffset + patch.hpc
		binary.LittleEndian.PutUint32(slice(ord, ord+4), uint32(patch.src.ord))

		rel := trampInfo.lpc - patch.hpc
		binary.LittleEndian.PutUint32(slice(patch.lpc+1, patch.hpc), uint32(rel))
	}

	if err := syscall.Mprotect(slice(lpc, hpc), normProt); err != nil {
		return nil, errs.Wrap(err)
	}

	return c, nil
}

const (
	allProt  = syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	normProt = syscall.PROT_READ | syscall.PROT_EXEC
)

func slice(low, high uint64) (buf []byte) {
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	hdr.Cap = int(high - low)
	hdr.Len = int(high - low)
	hdr.Data = uintptr(low)
	return buf
}

func applyPatch(name string) bool {
	if name == "monketor.trampoline" {
		return false
	}
	return true
}
