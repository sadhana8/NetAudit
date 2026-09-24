/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set ssh disabled=no address=0.0.0.0/0

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22,8291
