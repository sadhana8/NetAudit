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

/ip dns
set allow-remote-requests=yes

/ip firewall filter
add chain=input action=accept protocol=udp dst-port=53 in-interface-list=WAN
add chain=input action=drop

/tool mac-server
set allowed-interface-list=all

/tool mac-server mac-winbox
set allowed-interface-list=all

/tool mac-server ping
set enabled=yes

/ip neighbor discovery-settings
set discover-interface-list=all

/tool romon
set enabled=yes

/tool bandwidth-server
set enabled=yes authenticate=no

/ip proxy
set enabled=yes port=8080

/ip socks
set enabled=yes port=1080

/snmp
set enabled=yes

/snmp community
set [ find default=yes ] name=public address=0.0.0.0/0 security=none write-access=yes
