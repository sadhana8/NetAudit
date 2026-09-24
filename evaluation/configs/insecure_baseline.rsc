/interface ethernet
set [ find default-name=ether1 ] name=wan

/interface bridge
add name=bridge-lan

/ip service
set telnet disabled=no
set winbox disabled=no address=0.0.0.0/0

/ip address
add address=192.168.10.1/24 interface=bridge-lan
add address=192.168.10.1/24 interface=wan

/ip firewall filter
add chain=input action=accept
