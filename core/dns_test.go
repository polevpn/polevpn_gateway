package core

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestGetCurrentDns(t *testing.T) {

	out, err := exec.Command("bash", "-c", "networksetup -listallnetworkservices").Output()
	if err != nil {
		t.Log(string(out))
	} else {
		t.Log(string(out))
	}

	a := strings.Split(string(out), "\n")

	for _, v := range a {
		//networksetup -getdnsservers Wi-Fi
		out, err := exec.Command("bash", "-c", "networksetup -getdnsservers \""+v+"\"").Output()
		if err != nil {
			continue
		} else {
			t.Log(string(out))
		}

	}
}

func TestGetCurrentDns2(t *testing.T) {

	out, err := exec.Command("bash", "-c", "networksetup -listallnetworkservices").Output()
	if err != nil {
		t.Log(string(out))
	} else {
		t.Log(string(out))
	}

	a := strings.Split(string(out), "\n")

	for _, v := range a {
		//networksetup -getdnsservers Wi-Fi
		out, err := exec.Command("bash", "-c", "networksetup -getdnsservers \""+v+"\"").Output()
		if err != nil {
			continue
		} else {
			ip := net.ParseIP(strings.Trim(string(out), " \n\r"))
			if ip == nil {
				t.Log(ip, v, string(out), len(string(out)))
			} else {
				t.Log(ip, v, string(out), len(string(out)))
			}
		}

	}

}
