//go:build windows
// +build windows

package task

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
)

func CheckProxyEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		fmt.Println("无法打开注册表键:", err)
		return false
	}
	defer k.Close()

	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		fmt.Println("无法读取ProxyEnable值:", err)
		return false
	}

	return proxyEnable == 1
}
