package core

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/polevpn/elog"
	"github.com/polevpn/kcp-go/v5"
)

const (
	KCP_SHARED_KEY_LEN = 16
	CH_KCP_WRITE_SIZE  = 20
	KCP_MTU            = 1350
	KCP_RECV_WINDOW    = 2048
	KCP_SEND_WINDOW    = 2048
	KCP_READ_BUFFER    = 4194304
	KCP_WRITE_BUFFER   = 4194304
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

func (kc *KCPConn) Connect(routeServer string, sharedKey string) error {

	if len(sharedKey) != KCP_SHARED_KEY_LEN {
		return errors.New("sharedkey len must be 16")
	}
	block, _ := kcp.NewAESBlockCrypt([]byte(sharedKey))
	conn, err := kcp.DialWithOptions(routeServer, nil, block, 10, 3)

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
			kc.wch <- nil
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
		var preOffset = 0

		prefetch := make([]byte, 2)

		for {
			n, err := kc.conn.Read(prefetch[preOffset:])
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
					elog.Info(kc.String(), "conn closed")
				} else {
					elog.Error(kc.String(), "conn read exception:", err)
				}
				return
			}
			preOffset += n
			if preOffset >= 2 {
				break
			}
		}

		len := binary.BigEndian.Uint16(prefetch)

		if len < POLE_PACKET_HEADER_LEN {
			elog.Error("invalid packet len")
			continue
		}

		pkt := make([]byte, len)
		copy(pkt, prefetch)
		var offset uint16 = 2
		for {
			n, err := kc.conn.Read(pkt[offset:])
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
					elog.Info(kc.String(), "conn closed")
				} else {
					elog.Error(kc.String(), "conn read exception:", err)
				}
				return
			}
			offset += uint16(n)
			if offset >= len {
				break
			}
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

func (kc *KCPConn) write() {
	defer func() {
		kc.wg.Done()
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
