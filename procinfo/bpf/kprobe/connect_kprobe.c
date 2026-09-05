//go:build ignore

// connect_kprobe.c: kprobe/kretprobe fallback for when the kernel has no
// usable BTF (../fentry's attach fails or /sys/kernel/btf/vmlinux is
// absent). Compiled into its own object, independent of ../fentry and
// ../sockstate, so a verifier rejection in one mode can never block another
// -- see connect_fentry.c's file comment for why that matters.
//
// A kprobe alone can't see the return value, so this pairs a kprobe (to
// stash the sk pointer + pid keyed by tid) with a kretprobe (to read the
// state once we know connect() succeeded) via a scratch map. Kept
// deliberately symmetrical with ../fentry so both attach modes emit
// identical struct event values downstream.
#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
	__u64 timestamp_ns;
	__u64 skaddr; // struct sock * identity, for correlating a connection's own events across state changes
	__u32 pid;
	__u8 proto;
	__u8 ip_ver;
	__u16 local_port;
	__u16 remote_port;
	__u8 local_addr[16];
	__u8 remote_addr[16];
	__u32 new_state;
	__u8 source;
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

// Value is the sk pointer stored as a plain __u64, not a struct wrapping
// `struct sock *`: bpf2go's -type type-collection can't generate a Go
// binding for a struct containing a raw pointer field ("type *btf.Pointer:
// not supported"), and this map is BPF-internal scratch space the Go side
// never touches directly anyway.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32); // tid
	__type(value, __u64); // struct sock *, as an integer
} connect_args_map SEC(".maps");

static __always_inline int kprobe_connect_entry(struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;
	bpf_map_update_elem(&connect_args_map, &tid, &skp, BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
	return kprobe_connect_entry(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk)
{
	return kprobe_connect_entry(sk);
}

// sk here is a raw pointer, not BTF-trusted like an fentry/fexit argument
// would be: every field read goes through BPF_CORE_READ/BPF_CORE_READ_INTO,
// never a direct `sk->field` dereference followed by memcpy -- the
// verifier rejects that as an invalid memory access on this path.
static __always_inline void fill_addrs_v4(struct event *ev, __be32 saddr, __be32 daddr)
{
	ev->ip_ver = 4;
	__builtin_memcpy(ev->local_addr, &saddr, sizeof(saddr));
	__builtin_memcpy(ev->remote_addr, &daddr, sizeof(daddr));
}

static __always_inline void fill_addrs_v6(struct event *ev, struct sock *sk)
{
	ev->ip_ver = 6;
	BPF_CORE_READ_INTO(ev->local_addr, sk, __sk_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(ev->remote_addr, sk, __sk_common.skc_v6_daddr);
}

static __always_inline int kretprobe_connect_exit(int ret, int ip_ver)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&connect_args_map, &tid);
	if (!skp)
		return 0;
	struct sock *sk = (struct sock *)*skp;
	bpf_map_delete_elem(&connect_args_map, &tid);

	if (ret != 0 || !sk)
		return 0;

	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	// See ../fentry/connect_fentry.c's matching comment: struct event is
	// packed, so a plain `ev->skaddr = (__u64)sk;` gets lowered into
	// per-byte shifts of sk itself, which the verifier rejects as pointer
	// arithmetic on a still-pointer-typed register. The read helper keeps
	// the store an opaque call instead.
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

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret)
{
	return kretprobe_connect_exit(ret, 4);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret)
{
	return kretprobe_connect_exit(ret, 6);
}
