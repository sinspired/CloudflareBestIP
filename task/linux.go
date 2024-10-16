//go:build !windows
// +build !windows

package task

import (
	"fmt"
	"os"
)

func CheckProxyEnabled() bool {
	fmt.Println("如果使用WSL建议手动检查是否开启代理")
	return os.Getenv("HTTP_PROXY") != "" || os.Getenv("HTTPS_PROXY") != ""
}