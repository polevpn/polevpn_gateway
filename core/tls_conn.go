package core

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/polevpn/elog"
)

const (
	CH_TLS_WRITE_SIZE = 20
)

type TLSConn struct {
	conn    net.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	wg      *sync.WaitGroup
}

func NewTLSConn() *TLSConn {
	return &TLSConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		wg:      &sync.WaitGroup{},
	}
}

func (kc *TLSConn) Connect(routeServer string) error {

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "apple.com",
	}
	dialer := &tls.Dialer{
		Config: config,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", routeServer)

	if err != nil {
		return err
	}

	kc.conn = conn
	kc.wch = make(chan []byte, CH_TLS_WRITE_SIZE)
	kc.closed = false
	return nil
}

func (kc *TLSConn) Close() error {

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

func (kc *TLSConn) String() string {
	return kc.conn.LocalAddr().String() + "->" + kc.conn.RemoteAddr().String()
}

func (kc *TLSConn) IsClosed() bool {
	return kc.closed
}

func (kc *TLSConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	kc.handler[cmd] = handler
}

func (kc *TLSConn) read() {
	defer func() {
		kc.wg.Done()
		kc.Close()
	}()

	defer PanicHandler()

	for {

		prefetch := make([]byte, 2)

		_, err := io.ReadFull(kc.conn, prefetch)

		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				elog.Info(kc.String(), ",conn closed")
			} else {
				elog.Error(kc.String(), ",conn read exception:", err)
			}
			return
		}

		len := binary.BigEndian.Uint16(prefetch)

		if len < POLE_PACKET_HEADER_LEN {
			elog.Error("invalid packet len")
			continue
		}

		pkt := make([]byte, len)
		copy(pkt, prefetch)

		_, err = io.ReadFull(kc.conn, pkt[2:])

		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				elog.Info(kc.String(), ",conn closed")
			} else {
				elog.Error(kc.String(), ",conn read exception:", err)
			}
			return
		}

		kc.dispatch(pkt)

	}

}

func (kc *TLSConn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := kc.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, kc)
	} else {
		elog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (kc *TLSConn) drainWriteCh() {
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

func (kc *TLSConn) write() {
	defer func() {
		kc.wg.Done()
		kc.drainWriteCh()
		kc.Close()
	}()
	defer PanicHandler()

	for {
		select {
		case pkt, ok := <-kc.wch:
			if !ok {
				elog.Error("get pkt from write channel fail,maybe channel closed")
				return
			} else {
				if pkt == nil {
					elog.Info("exit write process")
					return
				}
				_, err := kc.conn.Write(pkt)
				if err != nil {
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						elog.Info(kc.String(), "conn closed")
					} else {
						elog.Error(kc.String(), "conn write exception:", err)
					}
					return
				}
			}
		}
	}
}

func (kc *TLSConn) Send(pkt []byte) {
	if kc.IsClosed() {
		elog.Debug("kcp connection is closed,can't send pkt")
		return
	}
	if kc.wch != nil {
		kc.wch <- pkt
	}
}

func (kc *TLSConn) StartProcess() {
	kc.wg.Add(2)
	go kc.read()
	go kc.write()
}
