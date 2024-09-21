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
	"os"
	"strings"
	"sync"
	"time"
)

type IPPort struct {
	IP   string
	Port string
}

const (
	timeout     = 50 * time.Second // 连接超时时间
	maxDuration = 50 * time.Second // 请求和读取响应的最大持续时间
	traceURL    = "https://cloudflare.com/cdn-cgi/trace" // 请求trace URL
	gptURL      = "https://chatgpt.com" // 请求GPT URL
)

// checkTrace 使用给定的IP和端口访问cloudflare.com/cdn-cgi/trace
func checkTrace(ipPort IPPort, wg *sync.WaitGroup, validIPs chan<- IPPort) {
	defer wg.Done()
	resp := httping(ipPort.IP, ipPort.Port, traceURL)
	if resp.StatusCode == http.StatusOK {
		validIPs <- ipPort
	}
}

// checkGptProxy 使用给定的IP和端口访问chatgpt.com，检查返回的页面是否包含"block"
func checkGptProxy(ipPort IPPort, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()
	resp := httping(ipPort.IP, ipPort.Port, gptURL)
	var buf bytes.Buffer
	_, err := io.Copy(&buf, resp.Body)
	if err != nil {
		fmt.Printf("读取响应体错误: %v\n", err)
		return
	}
	content := buf.String()
	if strings.Contains(content, "block") {
		results <- fmt.Sprintf("IP %s:%s - 被封锁", ipPort.IP, ipPort.Port)
	} else {
		results <- fmt.Sprintf("IP %s:%s - 正常", ipPort.IP, ipPort.Port)
	}
}

func httping(IP, Port, requestURL string) *http.Response {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(IP, Port))
	if err != nil {
		fmt.Printf("建立TCP连接错误 %s:%s - %s\n", IP, Port, err)
		return &http.Response{}
	}
	defer conn.Close()
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: maxDuration,
	}
	req, _ := http.NewRequest("GET", requestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("访问错误 %s - %s\n", net.JoinHostPort(IP, Port), err)
		return &http.Response{}
	}
	defer resp.Body.Close()
	return resp
}

func main() {
	flag.Parse()
	args := flag.Args()
	defaultIPPorts := []IPPort{
		{"8.8.8.8", "53"},
	}
	var ipPorts []IPPort
	if len(args) == 0 {
		fmt.Println("未提供IP:Port参数，使用默认值")
		ipPorts = defaultIPPorts
	} else {
		for _, arg := range strings.Split(args[0], ",") {
			parts := strings.Split(arg, ":")
			if len(parts) == 9 {
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
	validIPs := make(chan IPPort, len(ipPorts))
	results := make(chan string, len(ipPorts))
	for _, ipPort := range ipPorts {
		wg.Add(1)
		go checkTrace(ipPort, &wg, validIPs)
	}
	wg.Wait()
	close(validIPs)
	for ipPort := range validIPs {
		wg.Add(1)
		go checkGptProxy(ipPort, &wg, results)
	}
	wg.Wait()
	close(results)
	file, err := os.Create("results.txt")
	if err != nil {
		fmt.Printf("创建文件错误: %v\n", err)
		return
	}
	defer file.Close()
	for result := range results {
		fmt.Println(result)
		file.WriteString(result + "\n")
	}
}
