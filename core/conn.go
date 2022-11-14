package core

import "errors"

var ErrIPNotExist = errors.New("reconnect ip is not exist")
var ErrKeyVerify = errors.New("shared_key verify fail")
var ErrConnectUnknown = errors.New("server unknown error")
var ErrNetwork = errors.New("network error")

type Conn interface {
	Connect(routeServer string) error
	Close() error
	String() string
	IsClosed() bool
	SetHandler(cmd uint16, handler func(PolePacket, Conn))
	Send(pkt []byte)
	StartProcess()
}
