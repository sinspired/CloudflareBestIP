package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	// "os"
	// "strings"
	"time"

	"github.com/mattn/go-ieproxy"
)

const (
	timeout    = 10 * time.Second                 // 连接超时时间
	requestURL = "https://chatgpt.com/cdn-cgi/trace/" // 请求trace URL
)

var testIPs = []string{"1.1.1.1", "2.2.2.2"}

func main() {
	for _, ip := range testIPs {
		fmt.Println(ip)
		checkAccess(ip)
	}
}

func checkAccess(testIP string) {
	// 解析URL以确定协议和端口
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		fmt.Println("无效的URL:", err)
		return
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	// fmt.Printf("host:%s,port:%s\n", host, port)
	if port == "" {
		// 如果未指定端口，基于协议设置默认端口
		switch parsedURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			fmt.Println("未知协议:", parsedURL.Scheme)
			return
		}
	}

	// 设置连接超时的拨号器
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	host = testIP

	fmt.Printf("检测 host:%s,port:%s\n", host, port)
	// 创建一个带有超时的连接
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Printf("建立TCP连接错误 %s:%s - %s\n", host, port, err)
		return
	}
	defer conn.Close()

	proxyFunc := ieproxy.GetProxyFunc()
	// 设置HTTP客户端，使用自定义的拨号器
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 仅在首次连接时使用已建立的TCP连接
				if addr == net.JoinHostPort(host, port) {
					return conn, nil
				}
				return dialer.DialContext(ctx, network, addr)
			},
			Proxy: proxyFunc,
			// 为HTTPS设置TLS配置
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 如果需要验证证书，请删除此行
			},
		},
		Timeout: 10 * time.Second,
	}

	// 创建新的HTTP GET请求
	req, _ := http.NewRequest("GET", requestURL, nil)

	// 设置请求头中的用户代理
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	// 发送请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("访问错误 %s:%s - %s\n", host, port, err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应错误:", err)
		return
	}

	// 打印响应状态码和内容
	fmt.Println("响应状态码:", resp.StatusCode)
	fmt.Println("响应内容:\n", string(body))

	// // 将响应内容保存到以IP地址命名的文件中
	// fileName := fmt.Sprintf("%s.html", testIP)
	// err = os.WriteFile(fileName, body, 0o644)
	// if err != nil {
	// 	fmt.Println("写入文件错误:", err)
	// 	return
	// }
	// if strings.Contains(string(body), "Mozilla/5.0"){
	// 	fmt.Println("访问成功")
	// }
}
