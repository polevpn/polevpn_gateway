package main

import (
	"flag"
	"os"
	"os/signal"
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

func main() {

	flag.Parse()
	defer elog.Flush()

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
