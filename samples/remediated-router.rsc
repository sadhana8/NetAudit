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

/ip address
add address=192.168.88.1/24 interface=bridge-lan
add address=198.51.100.2/24 interface=wan

/ip pool
add name=lan-pool ranges=192.168.88.20-192.168.88.100

/ip dhcp-server
add name=dhcp-lan interface=bridge-lan address-pool=lan-pool

/ip dhcp-server network
add address=192.168.88.0/24 gateway=192.168.88.1

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh disabled=no address=192.168.88.0/24
set winbox disabled=no address=192.168.88.0/24
set api disabled=yes
set api-ssl disabled=yes

/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept in-interface-list=LAN protocol=tcp src-address=192.168.88.0/24 dst-port=22,8291
add chain=input action=drop
add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN
add chain=forward action=drop

/ip firewall nat
add chain=srcnat action=masquerade out-interface-list=WAN

/ip route
add dst-address=0.0.0.0/0 gateway=198.51.100.1
