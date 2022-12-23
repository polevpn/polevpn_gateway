package core

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/polevpn/anyvalue"
	"github.com/polevpn/elog"
	"github.com/polevpn/netstack/tcpip/header"
)

const (
	POLE_CLIENT_INIT        = 0
	POLE_CLIENT_RUNING      = 1
	POLE_CLIENT_CLOSED      = 2
	POLE_CLIENT_RECONNETING = 3
)

const (
	VERSION_IP_V4             = 4
	VERSION_IP_V6             = 6
	TUN_DEVICE_CH_WRITE_SIZE  = 2048
	HEART_BEAT_INTERVAL       = 10
	RECONNECT_TIMES           = 60
	RECONNECT_INTERVAL        = 5
	SOCKET_NO_HEARTBEAT_TIMES = 2
)

const (
	ERROR_LOGIN    = "login"
	ERROR_REGISTED = "registed"
	ERROR_NETWORK  = "network"
	ERROR_UNKNOWN  = "unknown"
	ERROR_IO       = "io"
)

type PoleVpnGateway struct {
	tunio             *TunIO
	conn              Conn
	state             int
	registed          bool
	routeServer       string
	sharedKey         string
	gatewayIp         string
	localNetWorks     []interface{}
	routeNetWorks     []interface{}
	acls              []interface{}
	lasttimeHeartbeat time.Time
	wg                *sync.WaitGroup
	deviceName        string
	networkmgr        NetworkManager
}

func NewPoleVpnGateway() *PoleVpnGateway {

	client := &PoleVpnGateway{
		conn:  nil,
		state: POLE_CLIENT_INIT,
		wg:    &sync.WaitGroup{},
	}
	return client
}

func (pc *PoleVpnGateway) Start(routeServer string, sharedKey string, gatewayIp string, localNetWorks []interface{}, routeNetWorks []interface{}, acls []interface{}) error {

	pc.routeServer = routeServer
	pc.sharedKey = sharedKey
	pc.gatewayIp = gatewayIp
	pc.localNetWorks = localNetWorks
	pc.routeNetWorks = routeNetWorks
	pc.acls = acls
	var err error

	if runtime.GOOS == "darwin" {
		pc.networkmgr = NewDarwinNetworkManager()
	} else if runtime.GOOS == "linux" {
		pc.networkmgr = NewLinuxNetworkManager()
	} else {
		return errors.New("os platform not support")
	}

	elog.Info("connect to ", routeServer)

	if strings.HasPrefix(routeServer, "tls://") {
		pc.routeServer = strings.Replace(routeServer, "tls://", "", -1)
		pc.conn = NewTLSConn()
	} else if strings.HasPrefix(routeServer, "kcp://") {
		pc.routeServer = strings.Replace(routeServer, "kcp://", "", -1)
		pc.conn = NewKCPConn()
	} else {
		return errors.New("route server scheme unknown")
	}

	err = pc.conn.Connect(pc.routeServer, pc.sharedKey)
	if err != nil {
		return err
	}

	elog.Info("connected")

	device := NewTunDevice()

	if err = device.Create(); err != nil {
		return err
	}

	elog.Info("create device name:", device.ifce.Name())

	pc.deviceName = device.ifce.Name()
	pc.tunio = NewTunIO(TUN_DEVICE_CH_WRITE_SIZE)
	pc.tunio.SetPacketHandler(pc.handleTunPacket)
	pc.tunio.AttachDevice(device)
	pc.tunio.StartProcess()

	pc.conn.SetHandler(CMD_REGISTER, pc.handlerRouteRegisterRespose)
	pc.conn.SetHandler(CMD_S2C_IPDATA, pc.handlerIPDataResponse)
	pc.conn.SetHandler(CMD_HEART_BEAT, pc.handlerHeartBeatRespose)
	pc.conn.SetHandler(CMD_CLIENT_CLOSED, pc.handlerClientClose)

	pc.conn.StartProcess()
	go pc.HeartBeat()

	pc.SendRouteRegister()

	pc.lasttimeHeartbeat = time.Now()

	pc.state = POLE_CLIENT_RUNING
	pc.wg.Add(1)
	return nil
}

func (pc *PoleVpnGateway) WaitStop() {
	pc.wg.Wait()
}

func (pc *PoleVpnGateway) handleTunPacket(pkt []byte) {

	if pkt == nil {
		elog.Error("tun device close exception")
		pc.Stop()
		return
	}
	version := pkt[0]
	version = version >> 4

	if version != VERSION_IP_V4 {
		return
	}
	pc.sendIPPacketToRemoteConn(pkt)

}

func (pc *PoleVpnGateway) sendIPPacketToRemoteConn(pkt []byte) {

	if pc.conn != nil {
		buf := make([]byte, POLE_PACKET_HEADER_LEN+len(pkt))
		copy(buf[POLE_PACKET_HEADER_LEN:], pkt)
		polepkt := PolePacket(buf)
		polepkt.SetCmd(CMD_C2S_IPDATA)
		polepkt.SetLen(uint16(len(buf)))
		pc.conn.Send(polepkt)
	} else {
		elog.Error("remote conn haven't setup")
	}

}

func (pc *PoleVpnGateway) handlerHeartBeatRespose(pkt PolePacket, conn Conn) {
	elog.Debug("received heartbeat")
	pc.lasttimeHeartbeat = time.Now()
}

func (pc *PoleVpnGateway) handlerClientClose(pkt PolePacket, conn Conn) {
	elog.Debug("socket closed")
	pc.state = POLE_CLIENT_RECONNETING
}

func (pc *PoleVpnGateway) checkAcls(ip net.IP) bool {

	find := false

	for _, network := range pc.acls {
		nets := network.(string)
		_, subnet, err := net.ParseCIDR(nets)

		if err != nil {
			continue
		}
		find = subnet.Contains(ip)

		if find {
			return find
		}
	}
	return find

}

func (pc *PoleVpnGateway) handlerIPDataResponse(pkt PolePacket, conn Conn) {

	ipv4pkg := header.IPv4(pkt.Payload())

	srcIp := ipv4pkg.SourceAddress().To4()

	if !pc.checkAcls(net.IP(srcIp)) {
		elog.Debug(srcIp, "reject access")
		return
	}

	pc.tunio.Enqueue(pkt[POLE_PACKET_HEADER_LEN:])
}

func (pc *PoleVpnGateway) handlerRouteRegisterRespose(pkt PolePacket, conn Conn) {
	elog.Info("received register route response")

	resp, err := anyvalue.NewFromJson(pkt.Payload())

	if err != nil {
		elog.Error("decode json fail,", err)
		go pc.Stop()
		return
	}

	if resp.Get("error").AsStr() != "" {
		elog.Error("register fail,", resp.Get("error").AsStr())
		go pc.Stop()
		return
	}

	if !pc.registed {

		err := pc.networkmgr.SetNetwork(pc.deviceName, pc.gatewayIp, pc.routeNetWorks)
		if err != nil {
			elog.Error("set network fail,", err)
			go pc.Stop()
			return
		}
		pc.registed = true
	}

}

func (pc *PoleVpnGateway) SendRouteRegister() {

	elog.Info("send register route request")
	body := anyvalue.New()
	body.Set("key", pc.sharedKey)
	body.Set("gateway", pc.gatewayIp)
	body.Set("network", pc.localNetWorks)

	bodyData, _ := body.EncodeJson()

	buf := make([]byte, POLE_PACKET_HEADER_LEN+len(bodyData))
	copy(buf[POLE_PACKET_HEADER_LEN:], bodyData)
	PolePacket(buf).SetCmd(CMD_REGISTER)
	PolePacket(buf).SetLen(uint16(len(buf)))

	pc.conn.Send(buf)
}

func (pc *PoleVpnGateway) SendHeartBeat() {

	elog.Debug("send heartbeat")

	buf := make([]byte, POLE_PACKET_HEADER_LEN)
	PolePacket(buf).SetCmd(CMD_HEART_BEAT)
	PolePacket(buf).SetLen(POLE_PACKET_HEADER_LEN)
	pc.conn.Send(buf)
}

func (pc *PoleVpnGateway) HeartBeat() {

	timer := time.NewTicker(time.Second * time.Duration(HEART_BEAT_INTERVAL))

	for range timer.C {
		if pc.state == POLE_CLIENT_CLOSED {
			timer.Stop()
			break
		}
		timeNow := time.Now()
		if pc.state == POLE_CLIENT_RECONNETING || timeNow.Sub(pc.lasttimeHeartbeat) > time.Second*HEART_BEAT_INTERVAL*SOCKET_NO_HEARTBEAT_TIMES {
			elog.Error("current connection seems like abnormal or closed,reconnect")
			pc.conn.Close()
			err := pc.conn.Connect(pc.routeServer, pc.sharedKey)
			if err != nil {
				elog.Error("connect route server fail,", err)
				continue
			}
			pc.state = POLE_CLIENT_RUNING
			pc.conn.StartProcess()
			pc.SendRouteRegister()
			pc.lasttimeHeartbeat = timeNow
		}
		pc.SendHeartBeat()
	}

}

func (pc *PoleVpnGateway) Stop() {

	elog.Info("stopping")

	if pc.state == POLE_CLIENT_CLOSED {
		elog.Error("client have been closed")
		return
	}
	elog.Info("remote connection stopping")
	if pc.conn != nil {
		pc.conn.Close()
	}
	elog.Info("remote connection stopped")

	elog.Info("tun device stopping")
	if pc.tunio != nil {
		pc.tunio.Close()
	}
	elog.Info("tun device stopped")
	pc.state = POLE_CLIENT_CLOSED

	pc.wg.Done()
	elog.Info("stopped")

}
