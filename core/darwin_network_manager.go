package core

import (
	"errors"
	"os/exec"

	"github.com/polevpn/elog"
)

type DarwinNetworkManager struct {
}

func NewDarwinNetworkManager() *DarwinNetworkManager {
	return &DarwinNetworkManager{}
}

func (nm *DarwinNetworkManager) setIPAddressAndEnable(tundev string, gatewayIp string) error {

	out, err := exec.Command("bash", "-c", "ifconfig "+tundev+" "+gatewayIp+" "+gatewayIp+" up").Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *DarwinNetworkManager) addRoute(cidr string, gw string) error {

	out, err := exec.Command("bash", "-c", "route -n add -net "+cidr+" "+gw).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) delRoute(cidr string) error {

	out, err := exec.Command("bash", "-c", "route -n delete -net "+cidr).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *DarwinNetworkManager) SetNetwork(device string, gatewayIp string, routes []interface{}) error {

	var err error

	elog.Infof("set tun device ip as %v", gatewayIp)
	err = nm.setIPAddressAndEnable(device, gatewayIp)
	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	for _, route := range routes {
		route := route.(string)
		elog.Info("add route ", route, "via", gatewayIp)
		err = nm.addRoute(route, gatewayIp)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}
	return nil
}

func (nm *DarwinNetworkManager) RestoreNetwork() {

}
