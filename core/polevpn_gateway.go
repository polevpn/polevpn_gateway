package core

import (
	"errors"
	"sync"
	"time"

	"github.com/polevpn/anyvalue"
	"github.com/polevpn/elog"
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
	SOCKET_NO_HEARTBEAT_TIMES = 3
)

const (
	CLIENT_EVENT_STARTED  = 1
	CLIENT_EVENT_STOPPED  = 2
	CLIENT_EVENT_ERROR    = 3
	CLIENT_EVENT_REGISTED = 4
)

const (
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
	mutex             *sync.Mutex
	routeServer       string
	sharedKey         string
	gatewayIp         string
	localNetWork      string
	routeNetWorks     []interface{}
	lasttimeHeartbeat time.Time
	wg                *sync.WaitGroup
	device            *TunDevice
	handler           func(int, *PoleVpnGateway, *anyvalue.AnyValue)
}

func NewPoleVpnGateway() *PoleVpnGateway {

	client := &PoleVpnGateway{
		conn:  nil,
		state: POLE_CLIENT_INIT,
		mutex: &sync.Mutex{},
		wg:    &sync.WaitGroup{},
	}
	return client
}

func (pc *PoleVpnGateway) AttachTunDevice(device *TunDevice) {
	pc.device = device
	if pc.tunio != nil {
		pc.tunio.Close()
	}

	pc.tunio = NewTunIO(TUN_DEVICE_CH_WRITE_SIZE)
	pc.tunio.SetPacketHandler(pc.handleTunPacket)
	pc.tunio.AttachDevice(device)
	pc.tunio.StartProcess()
}

func (pc *PoleVpnGateway) SetEventHandler(handler func(int, *PoleVpnGateway, *anyvalue.AnyValue)) {
	pc.handler = handler
}

func (pc *PoleVpnGateway) Start(routeServer string, sharedKey string, gatewayIp string, localNetWork string, routeNetWorks []interface{}) error {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state != POLE_CLIENT_INIT {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "client stoped or not init").Set("type", ERROR_UNKNOWN))
		}
		return errors.New("client stoped or not init")
	}

	pc.routeServer = routeServer
	pc.sharedKey = sharedKey
	pc.gatewayIp = gatewayIp
	pc.localNetWork = localNetWork
	pc.routeNetWorks = routeNetWorks
	var err error

	pc.conn = NewKCPConn()

	err = pc.conn.Connect(routeServer, sharedKey)
	if err != nil {
		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("error", "connet fail,"+err.Error()).Set("type", ERROR_NETWORK))
		}
		return err
	}
	pc.conn.SetHandler(CMD_ROUTE_REGISTER, pc.handlerRouteRegisterRespose)
	pc.conn.SetHandler(CMD_S2C_IPDATA, pc.handlerIPDataResponse)
	pc.conn.SetHandler(CMD_CLIENT_CLOSED, pc.handlerConnCloseEvent)
	pc.conn.SetHandler(CMD_HEART_BEAT, pc.handlerHeartBeatRespose)

	pc.conn.StartProcess()

	pc.SendRouteRegister()

	pc.lasttimeHeartbeat = time.Now()
	go pc.HeartBeat()
	pc.state = POLE_CLIENT_RUNING
	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STARTED, pc, nil)
	}
	pc.wg.Add(1)
	return nil
}

func (pc *PoleVpnGateway) CloseConnect(flag bool) {
	pc.conn.Close(flag)
}

func (pc *PoleVpnGateway) WaitStop() {
	pc.wg.Wait()
}

func (pc *PoleVpnGateway) handleTunPacket(pkt []byte) {

	if pkt == nil {
		pc.handler(CLIENT_EVENT_ERROR, pc, anyvalue.New().Set("type", ERROR_IO).Set("error", "tun device close exception"))
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

func (pc *PoleVpnGateway) handlerIPDataResponse(pkt PolePacket, conn Conn) {
	pc.tunio.Enqueue(pkt[POLE_PACKET_HEADER_LEN:])
}

func (pc *PoleVpnGateway) handlerConnCloseEvent(pkt PolePacket, conn Conn) {
	elog.Info("client closed")
}

func (pc *PoleVpnGateway) handlerRouteRegisterRespose(pkt PolePacket, conn Conn) {
	elog.Info("received route register")

	if pc.registed == false {
		av := anyvalue.New()
		av.Set("device", pc.device.GetInterface().Name())
		av.Set("gateway", pc.gatewayIp)
		av.Set("routes", pc.routeNetWorks)

		if pc.handler != nil {
			pc.handler(CLIENT_EVENT_REGISTED, pc, av)
		}
		pc.registed = true
	}

}

func (pc *PoleVpnGateway) SendRouteRegister() {

	body := anyvalue.New()
	body.Set("gateway", pc.gatewayIp)
	body.Set("network", pc.localNetWork)

	bodyData, _ := body.EncodeJson()

	buf := make([]byte, POLE_PACKET_HEADER_LEN+len(bodyData))
	copy(buf[POLE_PACKET_HEADER_LEN:], bodyData)
	PolePacket(buf).SetCmd(CMD_ROUTE_REGISTER)
	PolePacket(buf).SetLen(uint16(len(buf)))

	pc.conn.Send(buf)
}

func (pc *PoleVpnGateway) SendHeartBeat() {
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
		if timeNow.Sub(pc.lasttimeHeartbeat) > time.Second*HEART_BEAT_INTERVAL*SOCKET_NO_HEARTBEAT_TIMES {
			elog.Error("have not recevied heartbeat for", SOCKET_NO_HEARTBEAT_TIMES, "times,close current connection,reconnect")
			pc.conn.Close(false)
			err := pc.conn.Connect(pc.routeServer, pc.sharedKey)
			if err != nil {
				elog.Error("connect route server fail")
				return
			}
			pc.conn.StartProcess()
			pc.SendRouteRegister()
			pc.lasttimeHeartbeat = timeNow
		}
		pc.SendHeartBeat()
	}

}

func (pc *PoleVpnGateway) Stop() {

	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if pc.state == POLE_CLIENT_CLOSED {
		elog.Error("client have been closed")
		return
	}

	if pc.conn != nil {
		pc.conn.Close(false)
	}

	if pc.tunio != nil {
		pc.tunio.Close()
	}
	pc.state = POLE_CLIENT_CLOSED

	if pc.handler != nil {
		pc.handler(CLIENT_EVENT_STOPPED, pc, nil)
	}
	pc.wg.Done()
}
