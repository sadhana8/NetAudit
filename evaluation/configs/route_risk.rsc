/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/ip address
add address=192.168.1.2/24 interface=wan
add address=10.0.0.1/24 interface=bridge-lan

/ip route
add dst-address=invalid-destination gateway=192.168.1.1
add dst-address=172.16.0.0/24
add dst-address=172.17.0.0/24 gateway=missing-interface
add dst-address=172.18.0.0/24 gateway=203.0.113.1
add dst-address=172.19.0.0/24 gateway=192.168.1.2
add dst-address=172.20.0.0/24 gateway=192.168.1.0
add dst-address=172.21.0.0/24 gateway=wan check-gateway=ping
add dst-address=172.22.0.0/24 gateway=wan
add dst-address=172.23.0.0/24 gateway=192.168.1.1 distance=999
add dst-address=172.24.0.0/24 gateway=192.168.1.1
add dst-address=172.24.0.0/24 gateway=192.168.1.1
add dst-address=172.25.0.0/24 gateway=192.168.1.1 distance=5
add dst-address=172.25.0.0/24 type=blackhole distance=5
