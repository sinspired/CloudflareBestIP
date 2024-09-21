package task

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	// "regexp"
	"strings"
	"time"
)

const (
	timeout     = 50 * time.Second // 连接超时时间
	maxDuration = 50 * time.Second // 请求和读取响应的最大持续时间
	// requestURL  = "https://speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
	// requestURL = "https://chatgpt.com/cdn-cgi/trace/" // 请求trace URL
	requestURL = "https://chatgpt.com" // 请求trace URL
)

// checkIPPort 尝试连接到给定的IP和端口，并发送HTTP请求以获取响应内容
func CheckGptProxy(ip, port string) bool {

	// 设置连接超时的拨号器
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}

	// 创建一个带有超时的连接
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		// fmt.Printf("建立TCP连接错误 %s:%s - %s\n", ip, port, err)
		return false
	}
	defer conn.Close()

	// 设置HTTP客户端，使用自定义的拨号器
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			// 为HTTPS设置TLS配置
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 如果需要验证证书，请删除此行
			},
		},
		Timeout: maxDuration,
	}

	// 创建新的HTTP GET请求
	req, _ := http.NewRequest("GET", requestURL, nil)

	// 设置请求头中的用户代理
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	// 发送请求并获取响应
	resp, err := client.Do(req)
	if err != nil {
		// fmt.Printf("访问错误 %s - %s\n", net.JoinHostPort(ip, port), err)
		return false
	}
	defer resp.Body.Close()

	// 将响应体内容复制到缓冲区
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		// fmt.Printf("读取响应体错误: %v\n", err)
		return false
	}

	content := buf.String()
	// fmt.Printf("来自 %s 的响应内容:\n%s\n", net.JoinHostPort(ip, port), content)
	// if strings.Contains(content, "html") {
		// fmt.Printf("来自 %s 的请求，成功\n", net.JoinHostPort(ip, port))
	// }
	// fmt.Println(resp.Header)
	// fmt.Println(resp.StatusCode)
	fmt.Println(resp.Header.Get("Cf-Mitigated"))

	if strings.Contains(content, "blocked") {
		fmt.Println("已被封锁")
		return false
	} else {
		fmt.Println("网页端正常")
		return true
	}
}
