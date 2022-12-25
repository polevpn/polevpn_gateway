# PoleVPN SD-WAN virtual routing system polevpn_gateway

## polevpn gateway Description
* The polevpn gateway is a client based on the polevpn SD-WAN virtual routing system solution. With the [polevpn_router](https://github.com/polevpn/polevpn_router) server, it can solve the problem of getting through and accelerating the network in various areas of the enterprise
* polevpn gateway can be deployed on any version of linux system
* polevpn gateway is written based on golang language, easy to deploy, no dependencies
* polevpn gateway is based on virtual network card technology (tun/tap), realizes network three-layer data routing and forwarding

## polevpn gateway installation and use
* git clone https://github.com/polevpn/polevpn_gateway.git
* cd polevpn_gateway
* go build
* nohup ./polevpn_gateway -configPath=./config.json &

## polevpn gateway configuration instructions
```
{
"route_server": "kcp://127.0.0.1:443", //polevpn router server address, using kcp communication protocol, or tls://127.0.0.1:443 tls protocol, anti-gfw blocking update powerful
"key":"123456", //communication shared key
"gateway": "169.254.0.5",//virtual gateway ip, requests from the local network to other networks are forwarded through this gateway ip, and this ip is bound to the tun device
"local_network":"192.168.10.0/24", //The local network address segment cidr, this network address segment will be registered to the polevpn router server, if the router server matches the target address belongs to this network segment, it will be forwarded to this gateway
"route_networks":["169.254.0.0/16","172.31.0.0/16","192.168.199.0/24","192.168.1.0/24"] //The network address segment to be routed
}
```
## Local iptalbes rule settings
* The ip forward function must be enabled, by executing (echo 1 > /proc/sys/net/ipv4/ip_forward), or modifying the sysctl.conf file
* Add nat address masquerade (iptables -t nat -A POSTROUTING -s 169.254.0.0/16 -j MASQUERADE), this iptalbes rule is to allow data transmission between virtual gateways
* Allow other ip address packets of the local network to be routed through the local virtual network card (iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE)

## How do other machines in the local network access other remote network segments through the polevpn gateway machine (if the gateway is installed on the 192.168.10.100 machine)
* Method 1, add a routing rule to the gateway machine on other machines, such as (ip route add 172.31.0.0/16 via 192.168.10.100), which means accessing the network segment of 172.31.0.0/16 and forwarding to 192.168.10.100
* Method 2, add a routing rule to the gateway machine on the router where the local network is located
