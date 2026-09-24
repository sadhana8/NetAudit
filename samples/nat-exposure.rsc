/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/interface list
add name=WAN
add name=LAN

/interface list member
add interface=wan list=WAN
add interface=bridge-lan list=LAN

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN
add chain=srcnat action=masquerade out-interface-list=WAN
add chain=dstnat protocol=tcp dst-port=8080 in-interface-list=WAN
add chain=dstnat action=dst-nat protocol=tcp dst-port=8099 in-interface-list=WAN
add chain=dstnat action=dst-nat protocol=tcp dst-port=8081 in-interface-list=WAN to-addresses=999.1.1.1 to-ports=80
add chain=dstnat action=dst-nat protocol=tcp dst-port=8082 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=70000
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.10 to-ports=443
add chain=dstnat action=dst-nat protocol=tcp dst-port=8443 in-interface-list=WAN to-addresses=192.168.10.11 to-ports=443
add chain=dstnat action=dst-nat protocol=tcp dst-port=8291 in-interface-list=WAN to-addresses=192.168.10.20 to-ports=8291
add chain=dstnat action=dst-nat to-addresses=192.168.10.30
