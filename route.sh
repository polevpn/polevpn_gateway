echo 1 > /proc/sys/net/ipv4/ip_forward
#清除转发，添加169.254.0.0/16 网段nat 
iptables -t nat -A POSTROUTING -s 169.254.0.0/16 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE

