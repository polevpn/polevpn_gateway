# PoleVPN SD-WAN 虚拟路由系统 polevpn_gateway

## polevpn gateway 说明
* polevpn gateway 是基于 polevpn SD-WAN 虚拟路由系统方案实现的客户端，配合polevpn router 服务端，可以解决企业各区域网络打通，加速问题
* polevpn gateway 可以部署在任意版本的linux 系统上
* polevpn gateway 基于golang 语言编写，部署方便，没有依赖
* polevpn gateway 基于虚拟网卡技术（tun/tap）,实现网络三层数据路由转发

## polevpn gateway 安装使用
* git clone https://github.com/polevpn/polevpn_gateway.git
* cd polevpn_gateway 
* go build
* nohup ./polevpn_gateway -configPath=./config.json &

## polevpn gateway 配置说明
```
{
"route_server":"kcp://127.0.0.1:443", //polevpn router 服务器地址，用的是kcp 通信协议，也可以是wss://127.0.0.1:443 wss 协议，抗gfw 阻断更强
"shared_key":"!@#dFXemc$%*%^0K", //通信共享密钥
"gateway":"169.254.0.5",//虚拟网关ip，本地网络到其他网络请求通过这个网关ip 转发出去，这个ip 跟tun 设备绑定
"local_network":"192.168.10.0/24", //本地网络地址段cidr，这个网络地址段会注册到polevpn router 服务器，如果router 服务器匹配目标地址是属于这个网段，就转发给这个网关
"route_networks":["169.254.0.0/16","172.31.0.0/16","192.168.199.0/24","192.168.1.0/24"]  //要路由的网络地址段
}
```
## 本地iptalbes 规则设置
* 必须开启ip forward 功能，通过执行（echo 1 > /proc/sys/net/ipv4/ip_forward），或者修改sysctl.conf 文件
* 添加nat地址伪装 (iptables -t nat -A POSTROUTING -s 169.254.0.0/16 -j MASQUERADE)，这个iptalbes 规则是允许虚拟网关之间数据传输
* 允许本地网络其他ip 地址包通过本机的虚拟网卡路由出去（iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -j MASQUERADE）

## 本地网络的其他机器如何通过polevpn gateway 机器访问远程其他网段（假如gateway 安装在192.168.10.100这台机器上）
* 方法一，在其他机器添加一条路由规则到gateway 机器，比如（ip route add 172.31.0.0/16 via 192.168.10.100）,表示访问172.31.0.0/16 这个网段，转发到 192.168.10.100
* 方法二，在本地网络所在的路由器上添加一条路由规则到gateway 机器
