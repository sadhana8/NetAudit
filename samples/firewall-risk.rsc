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

/ip firewall filter
add chain=input action=drop
add chain=input action=accept connection-state=established,related
add chain=input action=drop connection-state=invalid
add chain=input action=accept protocol=tcp src-address=10.0.0.0/8 dst-port=22
add chain=input action=drop protocol=tcp src-address=10.1.0.0/16 dst-port=22
add chain=input action=accept protocol=tcp dst-port=22,8291 in-interface-list=WAN
add chain=input action=accept protocol=tcp dst-port=70000
add chain=input action=accept src-address=999.1.1.1
add chain=input action=accept protocol=tcp dst-port=8080
add chain=input action=accept protocol=tcp dst-port=8080
add chain=forward action=fasttrack-connection connection-state=established,related
add chain=forward action=accept
