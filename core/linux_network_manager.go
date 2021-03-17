package core

import (
	"errors"
	"os/exec"

	"github.com/polevpn/elog"
)

type LinuxNetworkManager struct {
}

func NewLinuxNetworkManager() *LinuxNetworkManager {
	return &LinuxNetworkManager{}
}

func (nm *LinuxNetworkManager) setIPAddressAndEnable(tundev string, gatewayIp string) error {

	var out []byte
	var err error

	out, err = exec.Command("bash", "-c", "ip addr add dev "+tundev+" local "+gatewayIp+" peer "+gatewayIp).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}

	out, err = exec.Command("bash", "-c", "ip link set "+tundev+" up").Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return nil
}

func (nm *LinuxNetworkManager) addRoute(cidr string, gw string) error {
	out, err := exec.Command("bash", "-c", "ip route add "+cidr+" via "+gw).Output()
	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err
}

func (nm *LinuxNetworkManager) delRoute(cidr string) error {

	out, err := exec.Command("bash", "-c", "ip route del "+cidr).Output()

	if err != nil {
		return errors.New(err.Error() + "," + string(out))
	}
	return err

}

func (nm *LinuxNetworkManager) SetNetwork(device string, gatewayIp string, routes []interface{}) error {

	var err error

	elog.Infof("set tun device ip as %v", gatewayIp)
	err = nm.setIPAddressAndEnable(device, gatewayIp)
	if err != nil {
		return errors.New("set address fail," + err.Error())
	}

	for _, route := range routes {
		route := route.(string)
		elog.Info("ip route add", route, "via", gatewayIp)
		err = nm.addRoute(route, gatewayIp)
		if err != nil {
			return errors.New("add route fail," + err.Error())
		}
	}
	return nil
}

func (nm *LinuxNetworkManager) RestoreNetwork() {

}
