package core

type NetworkManager interface {
	SetNetwork(device string, gatewayIp string, rotues []interface{}) error
	RestoreNetwork()
}
