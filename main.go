package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/polevpn/anyvalue"
	"github.com/polevpn/elog"
	"github.com/polevpn/polevpn_gateway/core"
)

var Config *anyvalue.AnyValue
var configPath string

func init() {
	flag.StringVar(&configPath, "config", "./config.json", "config file path")
}

func signalHandler(pc *core.PoleVpnGateway) {

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		for s := range c {
			switch s {
			case syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				elog.Info("receive exit signal,exit")
				if pc != nil {
					pc.Stop()
				}
				elog.Flush()
				os.Exit(0)
			default:
			}
		}
	}()
}

var networkmgr core.NetworkManager

func eventHandler(event int, client *core.PoleVpnGateway, av *anyvalue.AnyValue) {

	switch event {

	case core.CLIENT_EVENT_REGISTED:
		{
			err := networkmgr.SetNetwork(av.Get("device").AsStr(), av.Get("gateway").AsStr(), av.Get("routes").AsArray())
			if err != nil {
				elog.Error("set network fail,", err)
				go client.Stop()
			}
		}
	case core.CLIENT_EVENT_STOPPED:
		{
			elog.Info("client stoped")
			networkmgr.RestoreNetwork()
		}
	case core.CLIENT_EVENT_STARTED:
		elog.Info("client started")
	case core.CLIENT_EVENT_ERROR:
		elog.Info("client error", av.Get("error").AsStr())
	default:
		elog.Error("invalid evnet=", event)
	}

}

func main() {

	flag.Parse()
	defer elog.Flush()

	if runtime.GOOS == "darwin" {
		networkmgr = core.NewDarwinNetworkManager()
	} else if runtime.GOOS == "linux" {
		networkmgr = core.NewLinuxNetworkManager()
	} else {
		elog.Fatal("os platform not support")
	}

	var err error

	Config, err = core.GetConfig(configPath)
	if err != nil {
		elog.Fatal("load config fail", err)
	}

	device := core.NewTunDevice()
	err = device.Create()

	if err != nil {
		elog.Fatal("create device fail", err)
	}

	client := core.NewPoleVpnGateway()
	client.SetEventHandler(eventHandler)
	client.AttachTunDevice(device)

	routeServer := Config.Get("route_server").AsStr("127.0.0.1:443")
	sharedKey := Config.Get("shared_key").AsStr()
	gatewayIp := Config.Get("gateway").AsStr()
	localNetWork := Config.Get("local_network").AsStr()
	routeNetWorks := Config.Get("route_networks").AsArray()

	err = client.Start(routeServer, sharedKey, gatewayIp, localNetWork, routeNetWorks)
	if err != nil {
		elog.Fatal("start polevpn client fail", err)
	}

	signalHandler(client)

	client.WaitStop()
}
