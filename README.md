# dnsmon

This is a little program I wrote inspired by [passivedns](https://github.com/gamelinux/passivedns)

It logs all DNS packets it sees on a given interface

Sample output on Windows:

```powershell
INFO[0000] Prometheus endpoint: http://0.0.0.0:8080/metrics
INFO[0000] No flags specified, using defaults            interface="\Device\NPF_{2652E425-01C4-4EB5-AE0F-0DE011B69C61}" promiscuous=true snaplen=65536
INFO[0000] Listening on device: \Device\NPF_{2652E425-01C4-4EB5-AE0F-0DE011B69C61}
INFO[0003] QUERY                                         class=IN dst=8.8.8.8 id=19712 name=jawn.ca opcode=Query rcode="No Error" src=192.168.2.21 type=A
INFO[0003] QUERY                                         class=IN dst=192.168.2.21 id=19712 name=jawn.ca opcode=Query rcode="No Error" src=8.8.8.8 type=A
INFO[0003] ANSWER                                        class=IN dst=192.168.2.21 id=19712 ip=192.30.252.153 name=jawn.ca opcode=Query rcode="No Error" src=8.8.8.8 type=A
INFO[0003] ANSWER                                        class=IN dst=192.168.2.21 id=19712 ip=192.30.252.154 name=jawn.ca opcode=Query rcode="No Error" src=8.8.8.8 type=A
```

Metrics sponsored in part by prometheus #cloudnative

![grafana](https://raw.githubusercontent.com/j4wn/dnsmon-go/master/Screenshots/grafana.png)

