# enetmon (eBPF Network Monitor)

`enetmon` is a simple eBPF program that monitors TCP/UDP traffic and prints socket buffer information.

The following functions are hooked to display logs.
- TCP (fexit)
  - tcp_close
  - tcp_connect
  - tcp_disconnect
  - inet_csk_accept
  - tcp_shutdown
  - tcp_recvmsg
  - tcp_sendmsg
  - inet_csk_get_port
  - tcp_abort
- UDP (fexit)
  - udp_init_sock
  - udp_destroy_sock
  - udp_sendmsg
  - udp_recvmsg

The example is as follows.
- 192.168.10.19: local
- 192.168.10.17: remote

```shell
# ssh: connect to remote server
2023/12/29 17:50:42 TCP: ssh tcp_connect err="" TCP_SYN_SENT src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/16384)   
2023/12/29 17:50:42 TCP: ssh tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)
2023/12/29 17:50:42 TCP: ssh tcp_recvmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)
2023/12/29 17:50:42 TCP: ssh tcp_recvmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)

# ssh: close connection
2023/12/29 17:50:43 TCP: ssh tcp_recvmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)
2023/12/29 17:50:43 TCP: ssh tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)
2023/12/29 17:50:43 TCP: ssh tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)
2023/12/29 17:50:43 TCP: ssh tcp_close err="" TCP_FIN_WAIT1 src=192.168.10.19:47024 dst=192.168.10.17:22 rcv/snd(131072/87040)

# sshd: accept connection
2023/12/29 17:52:09 TCP: sshd inet_csk_accept err="" TCP_ESTABLISHED src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040)
2023/12/29 17:52:09 TCP: sshd tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040)
2023/12/29 17:52:09 TCP: sshd tcp_recvmsg err="" TCP_ESTABLISHED src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040)

# sshd: close connection
2023/12/29 17:52:10 TCP: sshd tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040)
2023/12/29 17:52:10 TCP: sshd tcp_recvmsg err="" TCP_CLOSE_WAIT src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040) 
2023/12/29 17:52:10 TCP: sshd tcp_close err="" TCP_LAST_ACK src=192.168.10.19:22 dst=192.168.10.17:60064 rcv/snd(131072/87040)   

# iperf: disconnect by peer (CTL-C iperf server)
2023/12/29 17:52:52 TCP: iperf tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:40706 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:40706 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_sendmsg err="" TCP_ESTABLISHED src=192.168.10.19:40706 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_sendmsg err="connection reset by peer" TCP_CLOSE src=192.168.10.19:0 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_sendmsg err="" TCP_CLOSE src=192.168.10.19:0 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_shutdown err="" TCP_CLOSE src=192.168.10.19:0 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:52 TCP: iperf tcp_close err="" TCP_CLOSE src=192.168.10.19:0 dst=192.168.10.17:5001 rcv/snd(131072/4194304)
2023/12/29 17:52:53 UDP: avahi-daemon udp_recvmsg err="" src=0.0.0.0:5353 dst=0.0.0.0:0 rcv/snd(212992/212992)
```

## Test environment

- OS: Ubuntu 22.04 (arm64)
- Kernel: 6.5.0-14
- go: 1.21.3
- bcc: 0.29.1
- cilium/ebpf: 0.12.3
- clang: 14.0.0

## Test results
I conducted 10 rounds of sending and receiving 10GB with iperf, but there was no performance difference.

test commands
```shell
for i in {1..10}; do (time  iperf -c xx.xx.xx.xx -n 10G) 2>&1 | grep real >> iperf_time.log; done
```

test conditions
- iperf client: enetmon disabled
- iperf client: enetmon enable
- iperf server: enetmon disabled
- iperf server: enetmon enable

## Links

reference code
- [cilium/ebpf: examples/fentry](https://github.com/cilium/ebpf/blob/main/examples/fentry)
- [go-conntracer-bpf](https://github.com/yuuki/go-conntracer-bpf)
