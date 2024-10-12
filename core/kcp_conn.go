package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/polevpn/anyvalue"
	"github.com/polevpn/elog"
	"github.com/polevpn/kcp"
)

const (
	CH_KCP_WRITE_SIZE = 20
	KCP_MTU           = 1350
	KCP_RECV_WINDOW   = 2048
	KCP_SEND_WINDOW   = 2048
	KCP_READ_BUFFER   = 4194304
	KCP_WRITE_BUFFER  = 4194304
)

type KCPConn struct {
	conn      *kcp.UDPSession
	sharedKey string
	wch       chan []byte
	closed    bool
	handler   map[uint16]func(PolePacket, Conn)
	wg        *sync.WaitGroup
}

func NewKCPConn() *KCPConn {
	return &KCPConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		wg:      &sync.WaitGroup{},
	}
}

func (kc *KCPConn) Connect(routeServer string, sharedKey string) error {

	udpAddr, err := net.ResolveUDPAddr("udp", routeServer)

	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	conn, err := kcp.DialWithContext(ctx, udpAddr)

	if err != nil {
		return err
	}
	conn.SetACKNoDelay(true)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(KCP_SEND_WINDOW, KCP_RECV_WINDOW)
	conn.SetReadBuffer(KCP_READ_BUFFER)
	conn.SetReadBuffer(KCP_WRITE_BUFFER)

	kc.sharedKey = sharedKey
	kc.conn = conn

	conn.SetDeadline(time.Now().Add(time.Second * 5))

	err = kc.auth()

	if err != nil {
		return err
	}

	kc.conn.SetDeadline(time.Time{})

	kc.wch = make(chan []byte, CH_KCP_WRITE_SIZE)
	kc.closed = false
	return nil
}

func (kc *KCPConn) auth() error {

	body := anyvalue.New()
	body.Set("key", kc.sharedKey)

	bodyData, _ := body.EncodeJson()

	buf := make([]byte, POLE_PACKET_HEADER_LEN+len(bodyData))
	copy(buf[POLE_PACKET_HEADER_LEN:], bodyData)
	PolePacket(buf).SetCmd(CMD_AUTH)
	PolePacket(buf).SetLen(uint16(len(buf)))

	_, err := kc.conn.Write(buf)

	if err != nil {
		return err
	}

	pkt, err := ReadPacket(kc.conn)

	if err != nil {
		return err
	}

	ppkt := PolePacket(pkt)

	av, err := anyvalue.NewFromJson(ppkt.Payload())

	if err != nil {
		return err
	}

	if av.Get("error").AsStr() != "" {
		return errors.New(av.Get("error").AsStr())
	}

	return nil

}

func (kc *KCPConn) Close() error {

	if !kc.closed {
		kc.closed = true
		if kc.wch != nil {
			close(kc.wch)
		}
		err := kc.conn.Close()
		kc.wg.Wait()

		pkt := make([]byte, POLE_PACKET_HEADER_LEN)
		PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
		go kc.dispatch(pkt)

		return err
	}
	return nil
}

func (kc *KCPConn) String() string {
	return kc.conn.LocalAddr().String() + "->" + kc.conn.RemoteAddr().String()
}

func (kc *KCPConn) IsClosed() bool {
	return kc.closed
}

func (kc *KCPConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	kc.handler[cmd] = handler
}

func (kc *KCPConn) read() {
	defer func() {
		kc.wg.Done()
		kc.Close()
	}()

	defer PanicHandler()

	for {

		pkt, err := ReadPacket(kc.conn)

		if err != nil {
			elog.Error(kc.String(), " read packet end status=", err)
			return
		}

		kc.dispatch(pkt)

	}

}

func (kc *KCPConn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := kc.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, kc)
	} else {
		elog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (kc *KCPConn) drainWriteCh() {
	for {
		select {
		case _, ok := <-kc.wch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

func (kc *KCPConn) write() {
	defer func() {
		kc.wg.Done()
		kc.drainWriteCh()
		kc.Close()
	}()
	defer PanicHandler()

	for {
		pkt, ok := <-kc.wch
		if !ok {
			elog.Error(kc.String(), ",channel closed")
			return
		}
		if pkt == nil {
			elog.Info(kc.String(), ",exit write process")
			return
		}
		_, err := kc.conn.Write(pkt)
		if err != nil {
			elog.Error(kc.String(), ",conn write packet end status=", err)
			return
		}
	}
}

func (kc *KCPConn) Send(pkt []byte) {
	if kc.IsClosed() {
		elog.Debug("kcp connection is closed,can't send pkt")
		return
	}
	if kc.wch != nil {
		kc.wch <- pkt
	}
}

func (kc *KCPConn) StartProcess() {
	kc.wg.Add(2)
	go kc.read()
	go kc.write()
}
