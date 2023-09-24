# Tcpdump

Listen to Source IP:

```
$ tcpdump src {IP}
```

Show traffic for protocol:

```
$ tcpdump icmp
```

(showing traffic that contains ping)

Use AND (&&), OR (||), EXCEPT(!) to group filters:

```
$ tcpdump -i ppp0 src {IP} and icmp
```

(Listen on interface ppp0 for source IP for ICMP traffic
