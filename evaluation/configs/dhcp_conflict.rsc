/interface bridge
add name=bridge-lan

/interface ethernet
set [ find default-name=ether1 ] name=wan

/ip address
add address=192.168.10.0/24 interface=bridge-lan
add address=192.168.20.255/24 interface=wan
add address=10.0.0.1/24 interface=bridge-lan
add address=10.0.0.2/24 interface=wan
add address=172.16.0.1/24

/ip pool
add name=bad-pool ranges=10.0.0.0-10.0.1.20
add name=overlap-pool ranges=10.0.0.10-10.0.0.30

/ip dhcp-server
add name=dhcp-lan interface=bridge-lan address-pool=bad-pool

/ip dhcp-server network
add address=10.0.0.0/24 gateway=10.0.0.10
add address=10.0.0.0/24 gateway=10.0.0.1
add address=invalid-network gateway=10.0.0.1
