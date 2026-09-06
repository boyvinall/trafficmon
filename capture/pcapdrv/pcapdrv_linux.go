//go:build linux

package pcapdrv

// This file is pcapdrv's Linux driver: it loads libpcap via dlopen at
// runtime rather than linking against it at build time, so a missing
// libpcap.so produces a clean Go error instead of the dynamic linker
// refusing to exec the binary at all.

/*
#include <dlfcn.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

typedef pcap_t *(*pcap_open_live_fn)(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
typedef void (*pcap_close_fn)(pcap_t *);
typedef int (*pcap_compile_fn)(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
typedef int (*pcap_setfilter_fn)(pcap_t *, struct bpf_program *);
typedef void (*pcap_freecode_fn)(struct bpf_program *);
typedef int (*pcap_datalink_fn)(pcap_t *);
typedef int (*pcap_stats_fn)(pcap_t *, struct pcap_stat *);
typedef int (*pcap_next_ex_fn)(pcap_t *, struct pcap_pkthdr **, const u_char **);
typedef char *(*pcap_geterr_fn)(pcap_t *);
typedef int (*pcap_findalldevs_fn)(pcap_if_t **, char *);
typedef void (*pcap_freealldevs_fn)(pcap_if_t *);

static pcap_open_live_fn fn_pcap_open_live;
static pcap_close_fn fn_pcap_close;
static pcap_compile_fn fn_pcap_compile;
static pcap_setfilter_fn fn_pcap_setfilter;
static pcap_freecode_fn fn_pcap_freecode;
static pcap_datalink_fn fn_pcap_datalink;
static pcap_stats_fn fn_pcap_stats;
static pcap_next_ex_fn fn_pcap_next_ex;
static pcap_geterr_fn fn_pcap_geterr;
static pcap_findalldevs_fn fn_pcap_findalldevs;
static pcap_freealldevs_fn fn_pcap_freealldevs;

static void set_pcap_open_live(void *p)    { fn_pcap_open_live = (pcap_open_live_fn)p; }
static void set_pcap_close(void *p)        { fn_pcap_close = (pcap_close_fn)p; }
static void set_pcap_compile(void *p)      { fn_pcap_compile = (pcap_compile_fn)p; }
static void set_pcap_setfilter(void *p)    { fn_pcap_setfilter = (pcap_setfilter_fn)p; }
static void set_pcap_freecode(void *p)     { fn_pcap_freecode = (pcap_freecode_fn)p; }
static void set_pcap_datalink(void *p)     { fn_pcap_datalink = (pcap_datalink_fn)p; }
static void set_pcap_stats(void *p)        { fn_pcap_stats = (pcap_stats_fn)p; }
static void set_pcap_next_ex(void *p)      { fn_pcap_next_ex = (pcap_next_ex_fn)p; }
static void set_pcap_geterr(void *p)       { fn_pcap_geterr = (pcap_geterr_fn)p; }
static void set_pcap_findalldevs(void *p)  { fn_pcap_findalldevs = (pcap_findalldevs_fn)p; }
static void set_pcap_freealldevs(void *p)  { fn_pcap_freealldevs = (pcap_freealldevs_fn)p; }

static pcap_t *shim_pcap_open_live(const char *dev, int snaplen, int promisc, int to_ms, char *errbuf) {
	return fn_pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
}
static void shim_pcap_close(pcap_t *p) { fn_pcap_close(p); }
static int shim_pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask) {
	return fn_pcap_compile(p, fp, str, optimize, netmask);
}
static int shim_pcap_setfilter(pcap_t *p, struct bpf_program *fp) { return fn_pcap_setfilter(p, fp); }
static void shim_pcap_freecode(struct bpf_program *fp) { fn_pcap_freecode(fp); }
static int shim_pcap_datalink(pcap_t *p) { return fn_pcap_datalink(p); }
static int shim_pcap_stats(pcap_t *p, struct pcap_stat *ps) { return fn_pcap_stats(p, ps); }
static int shim_pcap_next_ex(pcap_t *p, struct pcap_pkthdr **hdr, const u_char **data) {
	return fn_pcap_next_ex(p, hdr, data);
}
static char *shim_pcap_geterr(pcap_t *p) { return fn_pcap_geterr(p); }
static int shim_pcap_findalldevs(pcap_if_t **devs, char *errbuf) { return fn_pcap_findalldevs(devs, errbuf); }
static void shim_pcap_freealldevs(pcap_if_t *devs) { fn_pcap_freealldevs(devs); }
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func init() {
	OpenLive = openLive
	FindAllDevs = findAllDevs
}

// ErrLibraryNotFound is wrapped by loadLibrary's error whenever libpcap
// itself, or any symbol this driver needs from it, could not be resolved at
// runtime — the caller-visible signal that a runtime dependency is missing,
// distinct from a normal pcap operational error.
var ErrLibraryNotFound = errors.New("pcapdrv: libpcap not found")

// sonameCandidates covers the handful of libpcap SONAME variants seen across
// common Linux distros, in the order ldconfig would typically resolve them.
var sonameCandidates = []string{"libpcap.so.1", "libpcap.so.0.8", "libpcap.so"}

// neededSymbols lists every libpcap symbol this driver dlsyms. Any single
// one missing folds into the same ErrLibraryNotFound-wrapping error rather
// than a nil-pointer panic later, on the theory that an incomplete symbol
// set means an unexpectedly old or incompatible libpcap build.
var neededSymbols = []string{
	"pcap_open_live",
	"pcap_close",
	"pcap_compile",
	"pcap_setfilter",
	"pcap_freecode",
	"pcap_datalink",
	"pcap_stats",
	"pcap_next_ex",
	"pcap_geterr",
	"pcap_findalldevs",
	"pcap_freealldevs",
}

// dlopenFunc and dlsymFunc are package-level vars (mirroring
// capture/route_linux.go's runRoute convention) so tests can force
// "library not found"/"symbol not found" without needing libpcap actually
// absent from the test machine.
var (
	dlopenFunc = func(name string) (unsafe.Pointer, error) {
		cname := C.CString(name)
		defer C.free(unsafe.Pointer(cname))
		C.dlerror() // clear any existing error
		handle := C.dlopen(cname, C.RTLD_NOW|C.RTLD_GLOBAL)
		if handle == nil {
			return nil, errors.New(dlerrorString())
		}
		return handle, nil
	}
	dlsymFunc = func(handle unsafe.Pointer, symbol string) (unsafe.Pointer, error) {
		csym := C.CString(symbol)
		defer C.free(unsafe.Pointer(csym))
		C.dlerror() // clear any existing error
		sym := C.dlsym(handle, csym)
		if sym == nil {
			if errStr := dlerrorString(); errStr != "" {
				return nil, errors.New(errStr)
			}
			return nil, fmt.Errorf("symbol %s not found", symbol)
		}
		return sym, nil
	}
)

func dlerrorString() string {
	if errC := C.dlerror(); errC != nil {
		return C.GoString(errC)
	}
	return ""
}

var (
	loadOnce sync.Once
	loadErr  error
)

// loadLibrary dlopens libpcap and dlsyms every symbol this driver needs,
// exactly once. Every OpenLive/FindAllDevs call routes through it first.
func loadLibrary() error {
	loadOnce.Do(func() {
		var handle unsafe.Pointer
		var lastErr error
		for _, soname := range sonameCandidates {
			h, err := dlopenFunc(soname)
			if err == nil {
				handle = h
				lastErr = nil
				break
			}
			lastErr = err
		}
		if handle == nil {
			loadErr = fmt.Errorf(
				`%w: install libpcap (e.g. "apt install libpcap0.8" on Debian/Ubuntu, "dnf install libpcap" on Fedora): %w`,
				ErrLibraryNotFound, lastErr,
			)
			return
		}

		for _, sym := range neededSymbols {
			ptr, err := dlsymFunc(handle, sym)
			if err != nil {
				loadErr = fmt.Errorf(
					`%w: libpcap is missing symbol %q (an unexpectedly old or incompatible libpcap build?): %w`,
					ErrLibraryNotFound, sym, err,
				)
				return
			}
			bindSymbol(sym, ptr)
		}
	})
	return loadErr
}

// bindSymbol stores one resolved libpcap function pointer into its matching
// C-side fn_pcap_* global, which the shim_pcap_* wrappers call through.
func bindSymbol(name string, ptr unsafe.Pointer) {
	switch name {
	case "pcap_open_live":
		C.set_pcap_open_live(ptr)
	case "pcap_close":
		C.set_pcap_close(ptr)
	case "pcap_compile":
		C.set_pcap_compile(ptr)
	case "pcap_setfilter":
		C.set_pcap_setfilter(ptr)
	case "pcap_freecode":
		C.set_pcap_freecode(ptr)
	case "pcap_datalink":
		C.set_pcap_datalink(ptr)
	case "pcap_stats":
		C.set_pcap_stats(ptr)
	case "pcap_next_ex":
		C.set_pcap_next_ex(ptr)
	case "pcap_geterr":
		C.set_pcap_geterr(ptr)
	case "pcap_findalldevs":
		C.set_pcap_findalldevs(ptr)
	case "pcap_freealldevs":
		C.set_pcap_freealldevs(ptr)
	}
}

// linuxHandle adapts a dlopen-resolved pcap_t* to Handle.
type linuxHandle struct {
	p unsafe.Pointer
}

func openLive(iface string, snaplen int32, promisc bool, timeout time.Duration) (Handle, error) {
	if err := loadLibrary(); err != nil {
		return nil, err
	}

	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))

	errbuf := make([]C.char, C.PCAP_ERRBUF_SIZE)

	promiscInt := C.int(0)
	if promisc {
		promiscInt = C.int(1)
	}
	toMs := C.int(timeout.Milliseconds())

	p := C.shim_pcap_open_live(cIface, C.int(snaplen), promiscInt, toMs, &errbuf[0])
	if p == nil {
		return nil, fmt.Errorf("pcap_open_live: %s", C.GoString(&errbuf[0]))
	}
	return &linuxHandle{p: unsafe.Pointer(p)}, nil
}

func (h *linuxHandle) pcapT() *C.pcap_t {
	return (*C.pcap_t)(h.p)
}

func (h *linuxHandle) SetBPFFilter(expr string) error {
	cExpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cExpr))

	var bpf C.struct_bpf_program
	if C.shim_pcap_compile(h.pcapT(), &bpf, cExpr, 1, C.PCAP_NETMASK_UNKNOWN) != 0 { //nolint:gocritic // cgo pointer-conversion boilerplate, not a real duplicate expression
		return fmt.Errorf("pcap_compile: %s", C.GoString(C.shim_pcap_geterr(h.pcapT())))
	}
	defer C.shim_pcap_freecode(&bpf) //nolint:gocritic // cgo pointer-conversion boilerplate, not a real duplicate expression

	if C.shim_pcap_setfilter(h.pcapT(), &bpf) != 0 { //nolint:gocritic // cgo pointer-conversion boilerplate, not a real duplicate expression
		return fmt.Errorf("pcap_setfilter: %s", C.GoString(C.shim_pcap_geterr(h.pcapT())))
	}
	return nil
}

func (h *linuxHandle) LinkType() layers.LinkType {
	return layers.LinkType(C.shim_pcap_datalink(h.pcapT()))
}

func (h *linuxHandle) Stats() (Stats, error) {
	var s C.struct_pcap_stat
	if C.shim_pcap_stats(h.pcapT(), &s) != 0 {
		return Stats{}, fmt.Errorf("pcap_stats: %s", C.GoString(C.shim_pcap_geterr(h.pcapT())))
	}
	return Stats{
		PacketsReceived:  int(s.ps_recv),
		PacketsDropped:   int(s.ps_drop),
		PacketsIfDropped: int(s.ps_ifdrop),
	}, nil
}

func (h *linuxHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var hdr *C.struct_pcap_pkthdr
	var data *C.u_char

	switch C.shim_pcap_next_ex(h.pcapT(), &hdr, &data) { //nolint:gocritic // cgo pointer-conversion boilerplate, not a real duplicate expression
	case 1:
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(hdr.ts.tv_sec), int64(hdr.ts.tv_usec)*1000),
			CaptureLength: int(hdr.caplen),
			Length:        int(hdr.len),
		}
		buf := unsafe.Slice((*byte)(unsafe.Pointer(data)), int(hdr.caplen))
		return buf, ci, nil
	case 0:
		return nil, gopacket.CaptureInfo{}, ErrTimeoutExpired
	case -2:
		return nil, gopacket.CaptureInfo{}, io.EOF
	default:
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("pcap_next_ex: %s", C.GoString(C.shim_pcap_geterr(h.pcapT())))
	}
}

func (h *linuxHandle) Close() {
	C.shim_pcap_close(h.pcapT())
}

func findAllDevs() ([]string, error) {
	if err := loadLibrary(); err != nil {
		return nil, err
	}

	errbuf := make([]C.char, C.PCAP_ERRBUF_SIZE)
	var devs *C.pcap_if_t
	if C.shim_pcap_findalldevs(&devs, &errbuf[0]) != 0 { //nolint:gocritic // cgo pointer-conversion boilerplate, not a real duplicate expression
		return nil, fmt.Errorf("pcap_findalldevs: %s", C.GoString(&errbuf[0]))
	}
	defer C.shim_pcap_freealldevs(devs)

	var names []string
	for d := devs; d != nil; d = d.next {
		names = append(names, C.GoString(d.name))
	}
	return names, nil
}
