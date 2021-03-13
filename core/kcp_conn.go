package core

import (
	"encoding/binary"
	"io"
	"strings"
	"sync"

	"github.com/polevpn/elog"
	"github.com/polevpn/kcp-go/v5"
)

const (
	CH_KCP_WRITE_SIZE     = 100
	KCP_HANDSHAKE_TIMEOUT = 5
	KCP_MTU               = 1350
	KCP_RECV_WINDOW       = 2048
	KCP_SEND_WINDOW       = 2048
	KCP_READ_BUFFER       = 4194304
	KCP_WRITE_BUFFER      = 4194304
)

var KCP_KEY = []byte{0x17, 0xef, 0xad, 0x3b, 0x12, 0xed, 0xfa, 0xc9, 0xd7, 0x54, 0x14, 0x5b, 0x3a, 0x4f, 0xb5, 0xf6}

type KCPConn struct {
	conn    *kcp.UDPSession
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	mutex   *sync.Mutex
}

func NewKCPConn() *KCPConn {
	return &KCPConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		mutex:   &sync.Mutex{},
	}
}

func (kc *KCPConn) Connect(routeServer string, sharedKey string) error {

	block, _ := kcp.NewAESBlockCrypt(KCP_KEY)
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

	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	kc.conn = conn
	kc.wch = make(chan []byte, CH_KCP_WRITE_SIZE)
	kc.closed = false
	return nil
}

func (kc *KCPConn) Close(flag bool) error {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	if kc.closed == false {
		kc.closed = true
		if kc.wch != nil {
			kc.wch <- nil
			close(kc.wch)
		}
		err := kc.conn.Close()
		if flag {
			pkt := make([]byte, POLE_PACKET_HEADER_LEN)
			PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
			go kc.dispatch(pkt)
		}
		return err
	}
	return nil
}

func (kc *KCPConn) String() string {
	return kc.conn.LocalAddr().String() + "->" + kc.conn.RemoteAddr().String()
}

func (kc *KCPConn) IsClosed() bool {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	return kc.closed
}

func (kc *KCPConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	kc.handler[cmd] = handler
}

func (kc *KCPConn) read() {
	defer func() {
		kc.Close(true)
	}()

	defer PanicHandler()

	for {
		var preOffset = 0

		prefetch := make([]byte, 2)

		for {
			n, err := kc.conn.Read(prefetch[preOffset:])
			if err != nil {
				if err == io.EOF || strings.Index(err.Error(), "use of closed network connection") > -1 {
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
				if err == io.EOF || strings.Index(err.Error(), "use of closed network connection") > -1 {
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
	if kc.IsClosed() == true {
		elog.Debug("websocket connection is closed,can't send pkt")
		return
	}
	if kc.wch != nil {
		kc.wch <- pkt
	}
}

func (kc *KCPConn) StartProcess() {
	go kc.read()
	go kc.write()
}
