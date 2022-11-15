package core

import (
	"sync"

	"github.com/polevpn/elog"
)

const (
	IP4_HEADER_LEN = 20
	TCP_HEADER_LEN = 20
	UDP_HEADER_LEN = 8
	DNS_PORT       = 53
	MTU            = 1500
)

type TunIO struct {
	device  *TunDevice
	wch     chan []byte
	mtu     int
	handler func(pkt []byte)
	closed  bool
	size    int
	mutex   *sync.Mutex
}

func NewTunIO(size int) *TunIO {

	return &TunIO{
		closed: true,
		mtu:    MTU,
		size:   size,
		mutex:  &sync.Mutex{},
	}
}

func (t *TunIO) SetPacketHandler(handler func(pkt []byte)) {
	t.handler = handler
}

func (t *TunIO) AttachDevice(device *TunDevice) {

	t.wch = make(chan []byte, t.size)
	t.device = device
	t.closed = false
}

func (t *TunIO) Close() error {

	if t.closed {
		return nil
	}
	if t.wch != nil {
		t.wch <- nil
		close(t.wch)
	}
	t.closed = true
	var err error
	if t.device != nil {
		err = t.device.Close()
	}
	return err
}

func (t *TunIO) IsClosed() bool {
	return t.closed
}

func (t *TunIO) StartProcess() {
	go t.read()
	go t.write()
}

func (t *TunIO) read() {

	defer func() {
		if !t.closed {
			t.handler(nil) //notify close exception
		}
		t.Close()
	}()

	defer PanicHandler()

	for {
		pkt := make([]byte, t.mtu)
		n, err := t.device.GetInterface().Read(pkt)
		if err != nil {
			elog.Error("tun read end status=", err)
			return
		}
		pkt = pkt[:n]
		if t.handler != nil {
			t.handler(pkt)
		}
	}

}

func (t *TunIO) write() {
	defer func() {
		if !t.closed {
			t.handler(nil) //notify close exception
		}
		t.Close()
	}()
	defer PanicHandler()
	for {

		pkt, ok := <-t.wch
		if !ok {
			elog.Error("channel closed")
			return
		}
		if pkt == nil {
			elog.Info("exit write process")
			return
		}
		_, err := t.device.GetInterface().Write(pkt)
		if err != nil {
			elog.Error("tun write end status=", err)
			return
		}
	}
}

func (t *TunIO) Enqueue(pkt []byte) {

	if t.IsClosed() {
		elog.Debug("tun device have been closed")
		return
	}

	if t.wch != nil {
		t.wch <- pkt
	}
}
