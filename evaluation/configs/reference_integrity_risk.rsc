/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN

/interface list member
add interface=missing-list-member-interface list=WAN
add interface=wan list=MISSING-LIST

/interface vlan
add name=vlan30 interface=missing-parent vlan-id=30

/interface bridge port
add bridge=missing-bridge interface=missing-bridge-port

/ip address
add address=192.168.10.1/24 interface=missing-ip-interface

/ip pool
add name=lan-pool ranges=192.168.10.20-192.168.10.100

/ip dhcp-server
add address-pool=lan-pool interface=missing-dhcp-interface name=dhcp-lan

/ip firewall filter
add chain=input action=drop in-interface=missing-firewall-interface
add chain=forward action=accept out-interface-list=MISSING-FIREWALL-LIST

/ip firewall nat
add chain=srcnat action=masquerade out-interface=missing-nat-interface
add chain=dstnat action=dst-nat in-interface-list=MISSING-NAT-LIST protocol=tcp dst-port=443 to-addresses=192.168.10.10
