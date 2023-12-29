//go:build ignore

#include "common.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
char __license[] SEC("license") = "Dual MIT/GPL";

//-----------------------------------------------------------------------------
// Copy only the necessary parts from the Linux kernel header.
//-----------------------------------------------------------------------------
typedef int bool;
#define true 1
#define false 0
typedef int size_t;

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
	union {
		struct {
			__be32 skc_daddr; // Foreign IPv4 addr
			__be32 skc_rcv_saddr; // Bound local IPv4 addr
		};
	};
	union {
		struct {
			__be16 skc_dport; // placeholder for inet_dport/tw_dport
			__u16 skc_num; // placeholder for inet_num/tw_num
		};
	};
	short unsigned int skc_family; // network address family
	volatile unsigned char skc_state; // Connection state
	struct in6_addr skc_v6_daddr; // IPV6 destination address
	struct in6_addr skc_v6_rcv_saddr; // IPV6 source address
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common; // shared layout with inet_timewait_sock
	int sk_rcvbuf; // size of receive buffer in bytes
	int sk_sndbuf; // size of send buffer in bytes
	int sk_err; // last error
} __attribute__((preserve_access_index));

struct msghdr {
} __attribute__((preserve_access_index));

//-----------------------------------------------------------------------------
// eBPF data structures
//-----------------------------------------------------------------------------

#define RINGBUF_SIZE_16MB (1 << 24)
#define RINGBUF_SIZE_8MB (1 << 23)
#define RINGBUF_SIZE_4MB (1 << 22)
#define RINGBUF_SIZE_2MB (1 << 21)
#define RINGBUF_SIZE_1MB (1 << 20)
#define RINGBUF_SIZE_512KB (1 << 19)
#define RINGBUF_SIZE_256KB (1 << 18)
#define RINGBUF_SIZE_128KB (1 << 17)

#define DEFINE_RINGBUF_STRUCT(name, size)           \
	struct {                                    \
		__uint(type, BPF_MAP_TYPE_RINGBUF); \
		__uint(max_entries, (size));        \
	} name##_event SEC(".maps");

// Note: When sending or receiving a large number of packets, using a common ring buffer does not work well.
//       As a solution to this problem and for optimization, we use a separate ring buffer for each function.
DEFINE_RINGBUF_STRUCT(tcp_close, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_connect, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_v4_connect, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_v6_connect, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_disconnect, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(inet_csk_accept, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_shutdown, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_recvmsg, RINGBUF_SIZE_1MB)
DEFINE_RINGBUF_STRUCT(tcp_sendmsg, RINGBUF_SIZE_1MB)
DEFINE_RINGBUF_STRUCT(inet_csk_get_port, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(tcp_abort, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(udp_init_sock, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(udp_destroy_sock, RINGBUF_SIZE_128KB)
DEFINE_RINGBUF_STRUCT(udp_sendmsg, RINGBUF_SIZE_1MB)
DEFINE_RINGBUF_STRUCT(udp_recvmsg, RINGBUF_SIZE_1MB)

#define RINGBUF_EVENT(name) name##_event
#define RINGBUF_SUBMIT(sk, name, fn_type) submit_event(sk, &RINGBUF_EVENT(name), fn_type)

struct event {
	// task_struct
	u8 comm[TASK_COMM_LEN];

	// struct sock
	int sk_rcvbuf;
	int sk_sndbuf;
	int sk_err;

	// struct sock_common
	u16 sport; // __u16
	u16 dport; // __be16
	u32 saddr; // __be32
	u32 daddr; // __be32
	struct in6_addr v6_daddr;
	struct in6_addr v6_saddr;
	short unsigned int family;
	unsigned char state;

	// misc
	unsigned char fn_type;
};
struct event *unused __attribute__((unused));

enum {
	FN_INVALID = 0,
	TCP_CLOSE_EXIT,
	TCP_CONNECT_EXIT,
	TCP_V4_CONNECT_EXIT,
	TCP_V6_CONNECT_EXIT,
	TCP_DISCONNECT_EXIT,
	INET_CSK_ACCEPT_EXIT,
	TCP_SHUTDOWN_EXIT,
	TCP_RECVMSG_EXIT,
	TCP_SENDMSG_EXIT,
	INET_CSK_GET_PORT_EXIT,
	TCP_ABORT_EXIT,
	UDP_INIT_SOCK_EXIT,
	UDP_DESTROY_SOCK_EXIT,
	UDP_SENDMSG_EXIT,
	UDP_RECVMSG_EXIT,
};

static __always_inline bool is_ip_family(struct sock *sk)
{
	if (sk->__sk_common.skc_family != AF_INET && sk->__sk_common.skc_family != AF_INET6) {
		return false;
	}
	return true;
}

static __always_inline void populate_event(struct event *evt, struct sock *sk, unsigned char fn_type)
{
	// task_struct
	bpf_get_current_comm(&evt->comm, TASK_COMM_LEN);

	// struct sock
	evt->sk_rcvbuf = sk->sk_rcvbuf;
	evt->sk_sndbuf = sk->sk_sndbuf;
	evt->sk_err = sk->sk_err;

	// struct sock_common
	if (sk->__sk_common.skc_family == AF_INET) {
		evt->saddr = sk->__sk_common.skc_rcv_saddr;
		evt->daddr = sk->__sk_common.skc_daddr;
	} else {
		__builtin_memcpy(&evt->v6_daddr, &sk->__sk_common.skc_v6_daddr, 16);
		__builtin_memcpy(&evt->v6_saddr, &sk->__sk_common.skc_v6_rcv_saddr, 16);
	}
	evt->dport = bpf_ntohs(sk->__sk_common.skc_dport);
	evt->sport = sk->__sk_common.skc_num;
	evt->family = sk->__sk_common.skc_family;
	evt->state = sk->__sk_common.skc_state;

	// misc
	evt->fn_type = fn_type;
}

static __always_inline int submit_event(struct sock *sk, void *evt, unsigned char fn_type)
{
	if (!is_ip_family(sk)) {
		bpf_printk("not ip family\n");
		return 0;
	}

	evt = bpf_ringbuf_reserve(evt, sizeof(struct event), 0);
	if (!evt) {
		bpf_printk("reserve failed fn_type=%d\n", fn_type);
		return 0;
	}

	populate_event(evt, sk, fn_type);

	bpf_ringbuf_submit(evt, 0);

	return 0;
}

// void tcp_close(struct sock *sk, long timeout)
SEC("fexit/tcp_close")
int BPF_PROG(tcp_close_exit, struct sock *sk, long timeout)
{
	return RINGBUF_SUBMIT(sk, tcp_close, TCP_CLOSE_EXIT);
}

// int tcp_connect(struct sock *sk)
SEC("fexit/tcp_connect")
int BPF_PROG(tcp_connect_exit, struct sock *sk)
{
	return RINGBUF_SUBMIT(sk, tcp_connect, TCP_CONNECT_EXIT);
}

// int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	return RINGBUF_SUBMIT(sk, tcp_v4_connect, TCP_V4_CONNECT_EXIT);
}

// REQUIRE: CONFIG_KALLSYMS_ALL=y
// static int tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("fexit/tcp_v6_connect")
int BPF_PROG(tcp_v6_connect_exit, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	return RINGBUF_SUBMIT(sk, tcp_v6_connect, TCP_V6_CONNECT_EXIT);
}

// int tcp_disconnect(struct sock *sk, int flags)
SEC("fexit/tcp_disconnect")
int BPF_PROG(tcp_disconnect_exit, struct sock *sk, int flags)
{
	return RINGBUF_SUBMIT(sk, tcp_disconnect, TCP_DISCONNECT_EXIT);
}

// struct sock *inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit, struct sock *sk, int flags, int *err, bool kern, struct sock *ret)
{
	return RINGBUF_SUBMIT(ret, inet_csk_accept, INET_CSK_ACCEPT_EXIT);
}

// void tcp_shutdown(struct sock *sk, int how)
SEC("fexit/tcp_shutdown")
int BPF_PROG(tcp_shutdown_exit, struct sock *sk, int how)
{
	return RINGBUF_SUBMIT(sk, tcp_shutdown, TCP_SHUTDOWN_EXIT);
}

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)
SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)
{
	return RINGBUF_SUBMIT(sk, tcp_recvmsg, TCP_RECVMSG_EXIT);
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size)
{
	return RINGBUF_SUBMIT(sk, tcp_sendmsg, TCP_SENDMSG_EXIT);
}

// int inet_csk_get_port(struct sock *sk, unsigned short snum)
SEC("fexit/inet_csk_get_port")
int BPF_PROG(inet_csk_get_port_exit, struct sock *sk, unsigned short snum)
{
	return RINGBUF_SUBMIT(sk, inet_csk_get_port, INET_CSK_GET_PORT_EXIT);
}

// void tcp_abort(struct sock *sk, int err)
SEC("fexit/tcp_abort")
int BPF_PROG(tcp_abort_exit, struct sock *sk, int err)
{
	return RINGBUF_SUBMIT(sk, tcp_abort, TCP_ABORT_EXIT);
}

// int udp_init_sock(struct sock *sk)
SEC("fexit/udp_init_sock")
int BPF_PROG(udp_init_sock_exit, struct sock *sk)
{
	return RINGBUF_SUBMIT(sk, udp_init_sock, UDP_INIT_SOCK_EXIT);
}

// void udp_destroy_sock(struct sock *sk)
SEC("fexit/udp_destroy_sock")
int BPF_PROG(udp_destroy_sock_exit, struct sock *sk)
{
	return RINGBUF_SUBMIT(sk, udp_destroy_sock, UDP_DESTROY_SOCK_EXIT);
}

// int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("fexit/udp_sendmsg")
int BPF_PROG(udp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t len)
{
	return RINGBUF_SUBMIT(sk, udp_sendmsg, UDP_SENDMSG_EXIT);
}

// int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
	return RINGBUF_SUBMIT(sk, udp_recvmsg, UDP_RECVMSG_EXIT);
}