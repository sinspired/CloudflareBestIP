package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// func main() {
// 	dataUpdate("result_test.csv", "example.com", "your_token")
// }

// 移除BOM（字节顺序标记）
func removeBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		return data[3:]
	}
	return data
}

// 发送HTTP GET请求并处理重试逻辑
func sendGetRequest(client *http.Client, urlStr string, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Get(urlStr)
		if err == nil {
			return resp, nil
		}
		// fmt.Printf("请求失败（重试 %d/%d 次）：%v\n", i+1, maxRetries, err)
		fmt.Printf("请求失败（重试 %d/%d 次）\n", i+1, maxRetries)
		time.Sleep(1 * time.Second) // 等待2秒后重试
	}
	return nil, err
}

// 更新数据
func dataUpdate(fileName string, domain string, token string) {
	// 清除输出内容
	fmt.Print("\033[2J\033[0;0H")
	fmt.Printf("优选IP文件 %s 正在上传到 %s\n", fileName, domain)
	// 读取文件的前65行内容
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("读取文件时出错: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for i := 0; i < 65 && scanner.Scan(); i++ {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("扫描文件时出错: %v\n", err)
		return
	}

	// 将内容转换为UTF-8并进行Base64编码
	content := strings.Join(lines, "\n")
	contentBytes := removeBOM([]byte(content))
	base64Text := base64.StdEncoding.EncodeToString(contentBytes)

	// 构造更新URL
	updateUrlStr := fmt.Sprintf("https://%s/%s?token=%s&b64=%s&v=%d", domain, url.PathEscape(fileName), token, url.QueryEscape(base64Text), time.Now().Unix())

	// 设置HTTP客户端，启用Keep-Alive和重试逻辑
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,               // 最大空闲连接数
			IdleConnTimeout:     30 * time.Second, // 空闲连接的超时时间
			MaxIdleConnsPerHost: 2,                // 每个主机的最大空闲连接数
			DisableKeepAlives:   false,            // 启用 Keep-Alive
			// TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: time.Second * 30, // 设置单次请求超时时间为30秒
	}

	// 发送更新请求
	resp, err := sendGetRequest(client, updateUrlStr, 5) // 尝试重试5次
	if err != nil {
		fmt.Printf("自动更新失败,请手动上传文件或重新执行程序！\n %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 检查更新请求的状态码
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("更新请求失败，状态码: %d\n", resp.StatusCode)
		return
	}
	repeatCount := baseLens - len("发起数据更新请求[ok]")
	fmt.Printf("发起数据更新请求%s[\033[32mok\033[0m]\n", strings.Repeat(".", repeatCount))

	// 构造读取URL
	readUrlStr := fmt.Sprintf("https://%s/%s?token=%s&v=%d", domain, url.PathEscape(fileName), token, time.Now().Unix())

	// 发送读取请求
	resp, err = sendGetRequest(client, readUrlStr, 5) // 尝试重试5次
	if err != nil {
		fmt.Printf("发送读取请求时出错: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 检查读取请求的状态码
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("读取请求失败，状态码: %d\n", resp.StatusCode)
		return
	}

	// 读取响应内容
	readBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应时出错: %v\n", err)
		return
	}

	// 将读取到的内容移除BOM
	responseContent := removeBOM(readBody)
	originalContent := contentBytes

	// 比较发送的内容和响应内容
	equ := (string(responseContent) == string(originalContent))

	// 根据比较结果判断是否成功
	UrlStr := fmt.Sprintf("https://%s/%s?token=%s", domain, url.PathEscape(fileName), token)
	repeatCount = baseLens - len("验证数据更新结果[ok]")
	if equ {
		fmt.Printf("验证数据更新结果%s[\033[32mok\033[0m]\n\n", strings.Repeat(".", repeatCount))
		// fmt.Println(string(responseContent))
		fmt.Printf("\n\033[90m优选IP\033[0m \033[90;4m%s\033[0m \033[90m已成功更新 %d 条数据至:\033[0m\n\033[34m%s\033[0m\n", fileName, countQualified,UrlStr)
	} else {
		fmt.Printf("验证数据更新结果%s[\033[31mX\033[0m]\n", strings.Repeat(".", repeatCount))
	}
}
