//go:build ignore

// sockstate_tracepoint.c: the inet_sock_set_state tracepoint, fired on
// every TCP state transition for both inbound (accepted) and outbound
// connections -- unlike ../fentry/../kprobe's connect-only hooks, this is
// the only one of the three that also covers server-side sockets. Attached
// the same way regardless of which connect-hook mode (fentry/fexit or
// kprobe) ended up active: it's a classic TRACEPOINT program, not a Tracing
// one, so it doesn't participate in that branch at all. Kept in its own
// compiled object anyway so a rejection here can never block the connect
// hooks (or vice versa) -- see ../fentry/connect_fentry.c's file comment.
#include "../headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// vmlinux.h omits these -- they'd collide with an unrelated kernel enum of
// the same name -- so define them manually, same values as
// <linux/socket.h>.
#define AF_INET  2
#define AF_INET6 10

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

#define SOURCE_STATE_CHANGE 1

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

// vmlinux.h already declares struct trace_event_raw_inet_sock_set_state
// (it's a real kernel type once BTF is available) -- redeclaring it here
// collides with that declaration, so don't; field layout matches
// /sys/kernel/tracing/events/sock/inet_sock_set_state/format.
SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	// IPPROTO_TCP only; this tracepoint also fires for other protocols.
	if (ctx->protocol != IPPROTO_TCP)
		return 0;

	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	// See ../fentry/connect_fentry.c's matching comment: struct event is
	// packed, so a plain `ev->skaddr = (__u64)ctx->skaddr;` risks the
	// verifier's "pointer arithmetic with >>= operator prohibited" if
	// ctx->skaddr's value is still pointer-typed at that point. The read
	// helper keeps the store an opaque call instead of raw arithmetic.
	{
		__u64 skaddr = (__u64)ctx->skaddr;
		bpf_probe_read_kernel(&ev->skaddr, sizeof(ev->skaddr), &skaddr);
	}
	ev->pid = bpf_get_current_pid_tgid() >> 32;
	ev->proto = 0;
	ev->source = SOURCE_STATE_CHANGE;
	ev->new_state = ctx->newstate;
	ev->local_port = ctx->sport;
	ev->remote_port = ctx->dport;
	if (ctx->family == AF_INET) {
		// A scalar read through a cast, not an array-copying memcpy off
		// ctx, so it isn't subject to the "modified ctx ptr" rejection
		// below -- mirrors the v6 branch's reasoning in spirit, but this
		// direction happens to verify fine as a plain dereference.
		fill_addrs_v4(ev, *(__be32 *)ctx->saddr, *(__be32 *)ctx->daddr);
	} else {
		// A direct memcpy from ctx->saddr_v6/daddr_v6 computes further
		// arithmetic on an already-offset ctx pointer, which the verifier
		// rejects ("dereference of modified ctx ptr disallowed") -- go
		// through the read helper instead, which the verifier treats as an
		// opaque call rather than a raw pointer-chased access.
		ev->ip_ver = 6;
		bpf_probe_read_kernel(ev->local_addr, sizeof(ev->local_addr), ctx->saddr_v6);
		bpf_probe_read_kernel(ev->remote_addr, sizeof(ev->remote_addr), ctx->daddr_v6);
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
