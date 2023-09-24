# VMware LAN

### Configuration

* Settings --> Network Adapter 2 --> LAN Segment: LAN 1
* Have to configure static addresses for both the VMs

Windows:

* Search "Network Connections" --> right click on eth1 --> Properties --> Right Click Internet Protocol Version 4

Linux:

* `ifconfig eth1 192.168.200.10 netmask 255.255.255.0`
* `ip route add 192.168.200.0/24 dev eth1`
