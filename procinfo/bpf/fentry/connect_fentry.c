//go:build ignore

// connect_fentry.c: BTF fentry/fexit programs attributing outbound TCP
// connects to a PID. Preferred attach mode -- doesn't go through
// perf_event_open(2) (see procinfo/ebpf_linux.go's probe order), so this is
// tried before ../kprobe's fallback. Compiled into its own object so a
// verifier rejection here (or in ../kprobe, ../sockstate) can never block
// the other modes from loading -- cilium/ebpf verifies every program in a
// loaded collection together, so keeping attach-mode variants in separate
// objects is required, not stylistic.
//
// fexit, not fentry: tcp_v4_connect/tcp_v6_connect haven't necessarily
// committed inet_sk(sk)->inet_sport (the local port) to the sock yet on
// entry -- the kernel can still assign it during the call via
// inet_hash_connect(). Reading sk's fields after the traced function
// returns is what makes the local port and connect() return value both
// reliable.
#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// event is intentionally re-declared identically in ../kprobe and
// ../sockstate rather than shared: each attach-mode variant is a fully
// independent compiled object (see the file comment above), and bpf2go
// generates the matching Go struct per object, so there is no manual
// Go-side struct mirroring to keep in sync.
struct event {
	__u64 timestamp_ns; // bpf_ktime_get_ns() at event time
	__u64 skaddr;        // struct sock * identity, for correlating a connection's own events across state changes
	__u32 pid;
	__u8 proto;    // 0 = tcp, 1 = udp (unused today; always tcp)
	__u8 ip_ver;   // 4 or 6
	__u16 local_port;
	__u16 remote_port;
	__u8 local_addr[16];  // IPv4 uses the first 4 bytes only
	__u8 remote_addr[16]; // IPv4 uses the first 4 bytes only
	__u32 new_state;      // Linux TCP_* enum value from <net/tcp_states.h>
	__u8 source;          // 0 = connect, 1 = state_change
} __attribute__((packed));

// Never read: forces clang to retain struct event's full BTF type info so
// bpf2go's -type flag can find and generate it. Without a file-scope
// reference like this, an aggressive inliner can fold every use of
// `struct event *` down to raw offsets and the type vanishes from the
// compiled object's BTF entirely.
struct event *unused_event __attribute__((unused));

#define SOURCE_CONNECT 0

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

static __always_inline void fill_addrs_v4(struct event *ev, __be32 saddr, __be32 daddr)
{
	ev->ip_ver = 4;
	__builtin_memcpy(ev->local_addr, &saddr, sizeof(saddr));
	__builtin_memcpy(ev->remote_addr, &daddr, sizeof(daddr));
}

// sk isn't a BTF-trusted pointer even here in principle across kernel
// versions, so every field read goes through BPF_CORE_READ rather than a
// direct dereference -- keeps this identical in shape to the kprobe
// variant, where CO-RE reads are required, not optional.
static __always_inline void fill_addrs_v6(struct event *ev, struct sock *sk)
{
	ev->ip_ver = 6;
	BPF_CORE_READ_INTO(ev->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(ev->remote_addr, sk, __sk_common.skc_v6_daddr);
}

static __always_inline int emit_connect_event(struct sock *sk, int ret, int ip_ver)
{
	if (ret != 0)
		return 0; // connect() failed or is still in progress (-EINPROGRESS)

	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	// A plain `ev->skaddr = (__u64)sk;` gets the verifier's "pointer
	// arithmetic with >>= operator prohibited": struct event is packed, so
	// clang lowers that 8-byte store into per-byte shifts of sk itself --
	// still a BTF-trusted pointer register at that point, which the
	// verifier never allows to be shifted. Routing it through the read
	// helper (source: a plain stack local holding the same bit pattern)
	// keeps the store an opaque call instead of raw arithmetic on sk.
	{
		__u64 skaddr = (__u64)sk;
		bpf_probe_read_kernel(&ev->skaddr, sizeof(ev->skaddr), &skaddr);
	}
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->proto = 0;
	ev->source = SOURCE_CONNECT;
	ev->new_state = BPF_CORE_READ(sk, __sk_common.skc_state);
	// skc_num (unlike skc_dport) is already host byte order -- ntohs-ing it
	// would corrupt it into a different, essentially random port number.
	ev->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	ev->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (ip_ver == 4)
		fill_addrs_v4(ev, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),
			      BPF_CORE_READ(sk, __sk_common.skc_daddr));
	else
		fill_addrs_v6(ev, sk);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	return emit_connect_event(sk, ret, 4);
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
	return emit_connect_event(sk, ret, 6);
}
