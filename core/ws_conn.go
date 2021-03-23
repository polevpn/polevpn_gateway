package core

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/polevpn/elog"
)

const (
	CH_WEBSOCKET_WRITE_SIZE         = 20
	WEBSOCKET_HANDSHAKE_TIMEOUT     = 5
	WEBSOCKET_TCP_WRITE_BUFFER_SIZE = 5242880
	WEBSOCKET_TCP_READ_BUFFER_SIZE  = 5242880
)

type WebSocketConn struct {
	conn    *websocket.Conn
	wch     chan []byte
	closed  bool
	handler map[uint16]func(PolePacket, Conn)
	wg      *sync.WaitGroup
}

func NewWebSocketConn() *WebSocketConn {
	return &WebSocketConn{
		conn:    nil,
		closed:  true,
		wch:     nil,
		handler: make(map[uint16]func(PolePacket, Conn)),
		wg:      &sync.WaitGroup{},
	}
}

func (wsc *WebSocketConn) Connect(routeServer string, sharedKey string) error {

	var err error

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "apple.com",
	}

	netDialer := net.Dialer{LocalAddr: nil}

	netDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := netDialer.DialContext(ctx, network, addr)
		if err == nil {
			tcpconn := conn.(*net.TCPConn)
			tcpconn.SetNoDelay(true)
			tcpconn.SetKeepAlive(true)
			tcpconn.SetWriteBuffer(WEBSOCKET_TCP_WRITE_BUFFER_SIZE)
			tcpconn.SetReadBuffer(WEBSOCKET_TCP_READ_BUFFER_SIZE)
			tcpconn.SetKeepAlivePeriod(time.Second * 15)
		}
		return conn, err
	}

	d := websocket.Dialer{
		NetDialContext:    netDialContext,
		TLSClientConfig:   tlsconfig,
		HandshakeTimeout:  time.Second * WEBSOCKET_HANDSHAKE_TIMEOUT,
		EnableCompression: false,
	}

	conn, resp, err := d.Dial(routeServer+"?shared_key="+url.QueryEscape(sharedKey), nil)

	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusForbidden {
				return ErrKeyVerify
			} else {
				return ErrConnectUnknown
			}
		}
		elog.Error("websocket connect fail,", err)
		return ErrNetwork
	}

	wsc.conn = conn
	wsc.wch = make(chan []byte, CH_WEBSOCKET_WRITE_SIZE)
	wsc.closed = false
	return nil
}

func (wsc *WebSocketConn) Close() error {

	if !wsc.closed {
		wsc.closed = true
		if wsc.wch != nil {
			wsc.wch <- nil
			close(wsc.wch)
		}
		err := wsc.conn.Close()
		wsc.wg.Wait()
		pkt := make([]byte, POLE_PACKET_HEADER_LEN)
		PolePacket(pkt).SetCmd(CMD_CLIENT_CLOSED)
		go wsc.dispatch(pkt)
		return err
	}
	return nil
}

func (wsc *WebSocketConn) String() string {
	return wsc.conn.LocalAddr().String() + "->" + wsc.conn.RemoteAddr().String()
}

func (wsc *WebSocketConn) IsClosed() bool {
	return wsc.closed
}

func (wsc *WebSocketConn) SetHandler(cmd uint16, handler func(PolePacket, Conn)) {
	wsc.handler[cmd] = handler
}

func (wsc *WebSocketConn) read() {
	defer func() {
		wsc.wg.Done()
		wsc.Close()
	}()

	defer PanicHandler()

	for {
		mtype, pkt, err := wsc.conn.ReadMessage()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				elog.Info(wsc.String(), "conn closed")
			} else {
				elog.Error(wsc.String(), "conn read exception:", err)
			}
			return
		}
		if mtype != websocket.BinaryMessage {
			continue
		}

		wsc.dispatch(pkt)

	}

}

func (wsc *WebSocketConn) dispatch(pkt []byte) {
	ppkt := PolePacket(pkt)

	handler, ok := wsc.handler[ppkt.Cmd()]
	if ok {
		handler(pkt, wsc)
	} else {
		elog.Error("invalid pkt cmd=", ppkt.Cmd())
	}
}

func (wsc *WebSocketConn) write() {
	defer func() {
		wsc.wg.Done()
		wsc.Close()
	}()
	defer PanicHandler()

	for {
		select {
		case pkt, ok := <-wsc.wch:
			if !ok {
				elog.Error("get pkt from write channel fail,maybe channel closed")
				return
			} else {
				if pkt == nil {
					elog.Info("exit write process")
					return
				}
				err := wsc.conn.WriteMessage(websocket.BinaryMessage, pkt)
				if err != nil {
					if err == io.EOF || err == io.ErrUnexpectedEOF {
						elog.Info(wsc.String(), "conn closed")
					} else {
						elog.Error(wsc.String(), "conn write exception:", err)
					}
					return
				}
			}
		}
	}
}

func (wsc *WebSocketConn) Send(pkt []byte) {
	if wsc.IsClosed() {
		elog.Debug("websocket connection is closed,can't send pkt")
		return
	}
	if wsc.wch != nil {
		wsc.wch <- pkt
	}
}

func (wsc *WebSocketConn) StartProcess() {
	wsc.wg.Add(2)
	go wsc.read()
	go wsc.write()
}
