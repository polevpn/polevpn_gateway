package core

import (
	"os"

	"github.com/polevpn/water"
)

type TunDevice struct {
	ifce *water.Interface
}

func NewTunDevice() *TunDevice {
	return &TunDevice{}
}

func (td *TunDevice) Create() error {
	config := water.Config{
		DeviceType: water.TUN,
	}
	ifce, err := water.New(config)
	if err != nil {
		return err
	}
	td.ifce = ifce
	return nil
}

func (td *TunDevice) Attach(fd int) {

	td.ifce = water.NewInterface("tun", os.NewFile(uintptr(fd), "tun"), false)

}

func (td *TunDevice) GetInterface() *water.Interface {
	return td.ifce
}

func (td *TunDevice) Close() error {
	return td.ifce.Close()
}
