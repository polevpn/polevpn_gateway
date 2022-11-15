package core

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
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
	conn    *kcp.UDPSession
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	wg      *sync.WaitGroup
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

func (kc *KCPConn) Connect(routeServer string) error {

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		InsecureSkipVerify: true,
		ServerName:         "apple.com",
		MTU:                1400,
	}

	udpAddr, err := net.ResolveUDPAddr("udp", routeServer)

	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	conn, err := kcp.DialWithContext(ctx, udpAddr, config)

	if err != nil {
		return err
	}
	conn.SetMtu(KCP_MTU)
	conn.SetACKNoDelay(true)
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetWindowSize(KCP_SEND_WINDOW, KCP_RECV_WINDOW)
	conn.SetReadBuffer(KCP_READ_BUFFER)
	conn.SetReadBuffer(KCP_WRITE_BUFFER)

	kc.conn = conn
	kc.wch = make(chan []byte, CH_KCP_WRITE_SIZE)
	kc.closed = false
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
