package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type IPPort struct {
	IP   string
	Port string
}

const (
	timeout     = 50 * time.Second                             // 连接超时时间
	maxDuration = 50 * time.Second                             // 请求和读取响应的最大持续时间
	requestURL  = "https://speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
	// requestURL = "https://chatgpt.com/cdn-cgi/trace/" // 请求trace URL
)

// checkIPPort 尝试连接到给定的IP和端口，并发送HTTP请求以获取响应内容
func checkIPPort(ipPort IPPort, wg *sync.WaitGroup) string{
	defer wg.Done() // 确保WaitGroup计数器在函数结束时递减

	// 设置连接超时的拨号器
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}

	// 创建一个带有超时的连接
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ipPort.IP, ipPort.Port))
	if err != nil {
		fmt.Printf("建立TCP连接错误 %s:%s - %s\n", ipPort.IP, ipPort.Port, err)
		return
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
		fmt.Printf("访问错误 %s - %s\n", net.JoinHostPort(ipPort.IP, ipPort.Port), err)
		return
	}
	defer resp.Body.Close()

	// 将响应体内容复制到缓冲区
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		fmt.Printf("读取响应体错误: %v\n", err)
		return
	}

	content := buf.String()
	fmt.Printf("来自 %s 的响应内容:\n%s\n", net.JoinHostPort(ipPort.IP, ipPort.Port), content)
	if strings.Contains(content, "html") {
		fmt.Printf("来自 %s 的请求，成功\n", net.JoinHostPort(ipPort.IP, ipPort.Port))
	}
	// 检查响应体是否包含指定的用户代理
	if strings.Contains(content, "uag=Mozilla/5.0") {
		// 使用正则表达式提取colo字段和loc字段
		coloRegex := regexp.MustCompile(`colo=([A-Z]+)`)
		locRegex := regexp.MustCompile(`loc=([A-Z]+)`)

		coloMatches := coloRegex.FindStringSubmatch(content)
		locMatches := locRegex.FindStringSubmatch(content)

		if len(coloMatches) > 1 && len(locMatches) > 1 {
			colo := coloMatches[1]
			loc := locMatches[1]
			fmt.Printf("IP %s:%s - colo: %s, loc: %s\n", ipPort.IP, ipPort.Port, colo, loc)
		} else {
			fmt.Printf("未找到 colo 或 loc 字段 - IP %s:%s\n", ipPort.IP, ipPort.Port)
		}
	}
}

func main() {
	// 定义命令行参数
	flag.Parse()
	args := flag.Args()

	// 默认的IP和端口
	defaultIPPorts := []IPPort{
		{"8.8.8.8", "53"},
	}

	var ipPorts []IPPort

	if len(args) == 0 {
		fmt.Println("未提供IP:Port参数，使用默认值")
		ipPorts = defaultIPPorts
	} else {
		// 解析输入的IP和端口列表
		for _, arg := range strings.Split(args[0], ",") {
			parts := strings.Split(arg, ":")
			if len(parts) == 9 {
				// ipv6格式：2a05:d014:ed:9600:f52b:ab01:6bb:bc9d
				ipv6 := strings.Join(parts[0:8], ":")
				port := parts[8]
				ipPorts = append(ipPorts, IPPort{ipv6, port})
			} else if len(parts) == 2 {
				ipPorts = append(ipPorts, IPPort{IP: parts[0], Port: parts[1]})
			} else {
				fmt.Printf("无效的IP:Port格式: %s\n", arg)
				continue
			}
		}
	}

	var wg sync.WaitGroup

	// 逐个检查IP和端口，使用goroutine实现并发
	for _, ipPort := range ipPorts {
		wg.Add(1)
		go checkIPPort(ipPort, &wg)
	}

	// 等待所有goroutine完成
	wg.Wait()
}
