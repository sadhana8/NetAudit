# NetAudit intentionally insecure RouterOS sample
/interface bridge
add name=bridge-lan
/interface ethernet
set [ find default-name=ether1 ] name=wan
set [ find default-name=ether2 ] name=lan
/ip address
add address=192.168.10.1/24 interface=bridge-lan
add address=192.168.10.1/24 interface=lan
add address=192.168.10.129/25 interface=lan
/ip pool
add name=pool-main ranges=192.168.10.10-192.168.10.200
add name=pool-overlap ranges=192.168.10.150-192.168.10.220
/ip dhcp-server
add address-pool=missing-pool interface=bridge-lan name=dhcp-main
/ip dhcp-server network
add address=192.168.10.0/24 dns-server=8.8.8.8
/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set ssh address=0.0.0.0/0 disabled=no
set winbox address=0.0.0.0/0 disabled=no
set api address=0.0.0.0/0 disabled=no
set api-ssl certificate=none disabled=no
/ip firewall filter
add chain=input action=accept comment="Dangerous accept all"
add chain=input action=drop protocol=tcp dst-port=23 comment="This rule is unreachable"
add chain=input action=drop connection-state=invalid disabled=yes
/ip firewall nat
add chain=srcnat action=masquerade out-interface=wan
add chain=srcnat action=masquerade out-interface=wan
add chain=dstnat action=dst-nat protocol=tcp dst-port=3389 to-addresses=192.168.10.50
