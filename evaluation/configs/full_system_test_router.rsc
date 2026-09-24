# NetAudit full system test file
# Purpose: trigger audit result, topology, attack surface, hardening, DHCP, NAT, route, service, and firewall checks.
# Safe sample only. No real passwords, tokens, or private credentials.

/system identity
set name="NetAudit-Full-System-Test"

/interface ethernet
set [ find default-name=ether1 ] name=wan comment="ISP uplink"
set [ find default-name=ether2 ] name=lan comment="Main LAN"
set [ find default-name=ether3 ] name=guest comment="Guest LAN"

/interface bridge
add name=bridge-lan comment="Internal bridge"
add name=bridge-guest comment="Guest bridge"

/interface bridge port
add bridge=bridge-lan interface=lan
add bridge=bridge-guest interface=guest
add bridge=missing-bridge interface=ether5
add bridge=bridge-lan interface=missing-interface

/interface list
add name=WAN
add name=LAN
add name=GUEST

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN
add interface=bridge-guest list=GUEST
add interface=ghost-port list=LAN
add interface=lan list=MISSING_LIST

/ip address
add address=203.0.113.10/24 interface=wan comment="documentation public test range"
add address=192.168.10.1/24 interface=bridge-lan
add address=192.168.20.1/24 interface=bridge-guest
add address=192.168.10.255/24 interface=bridge-lan comment="broadcast address misuse"
add address=10.0.0.5/24 interface=missing-interface
add address=bad-address interface=bridge-lan

/ip pool
add name=lan-pool ranges=192.168.10.10-192.168.10.200
add name=guest-pool ranges=192.168.20.10-192.168.20.200
add name=overlap-lan ranges=192.168.10.150-192.168.10.250
add name=bad-pool ranges=192.168.30.0-192.168.31.20

/ip dhcp-server
add name=dhcp-lan interface=bridge-lan address-pool=lan-pool disabled=no
add name=dhcp-guest interface=bridge-guest address-pool=guest-pool disabled=no
add name=dhcp-missing interface=ghost-port address-pool=missing-pool disabled=no

/ip dhcp-server network
add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=8.8.8.8
add address=192.168.10.0/24 gateway=192.168.10.254 dns-server=1.1.1.1
add address=192.168.20.0/24 gateway=192.168.20.254
add address=invalid-network gateway=192.168.20.1

/ip service
set telnet disabled=no address=0.0.0.0/0
set ftp disabled=no address=0.0.0.0/0
set www disabled=no address=0.0.0.0/0
set winbox disabled=no address=0.0.0.0/0
set api disabled=no address=0.0.0.0/0
set ssh disabled=no address=192.168.10.0/24

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=8291 in-interface-list=WAN comment="WAN WinBox exposed"
add chain=input action=accept protocol=tcp dst-port=22 in-interface-list=WAN comment="WAN SSH exposed"
add chain=input action=accept protocol=tcp dst-port=80 in-interface-list=WAN comment="WAN web exposed"
add chain=input action=accept protocol=tcp dst-port=8728 in-interface-list=WAN comment="WAN API exposed"
add chain=input action=accept connection-state=established,related
add chain=input action=accept protocol=tcp dst-port=8291 in-interface-list=WAN comment="duplicate risky accept"
add chain=input action=accept protocol=tcp dst-port=70000 comment="invalid port"
add chain=input action=accept src-address=999.1.1.1 comment="invalid source"
add chain=input action=drop connection-state=invalid
add chain=input action=drop comment="default drop placed late"
add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept in-interface-list=WAN out-interface-list=LAN comment="broad WAN to LAN accept"
add chain=forward action=accept

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN
add chain=srcnat action=masquerade out-interface-list=WAN comment="duplicate masquerade"
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443 comment="HTTPS forward"
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443 comment="duplicate HTTPS forward"
add chain=dstnat action=dst-nat protocol=tcp dst-port=8291 in-interface-list=WAN to-addresses=192.168.10.20 to-ports=8291 comment="WinBox forward"
add chain=dstnat action=dst-nat protocol=tcp dst-port=8081 in-interface-list=WAN to-addresses=999.1.1.1 to-ports=80 comment="invalid target"
add chain=dstnat action=dst-nat protocol=tcp dst-port=8082 in-interface-list=WAN to-addresses=192.168.10.30 to-ports=70000 comment="invalid translated port"
add chain=dstnat protocol=tcp dst-port=8080 in-interface-list=WAN comment="missing action and target"
add chain=dstnat action=dst-nat to-addresses=192.168.10.40 comment="missing matching fields"

/ip route
add dst-address=0.0.0.0/0 gateway=203.0.113.1 distance=1
add dst-address=0.0.0.0/0 gateway=203.0.113.1 distance=1 comment="duplicate default route"
add dst-address=10.10.0.0/16 gateway=192.168.99.1 distance=1 comment="gateway not on local subnet"
add dst-address=172.16.0.0/16 gateway=missing-interface distance=1 comment="invalid gateway value"
add dst-address=bad-route gateway=192.168.10.1

/tool mac-server
set allowed-interface-list=all

/tool mac-server mac-winbox
set allowed-interface-list=all

/ip neighbor discovery-settings
set discover-interface-list=all