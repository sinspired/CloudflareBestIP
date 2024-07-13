package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-ieproxy"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/sinspired/CloudflareBestIP/task"
)

// 定义终端命令行变量
var (
	File             = flag.String("file", "txt.zip", "IP地址文件名称(*.txt或*.zip)")                     // IP地址文件名称
	outFile          = flag.String("outfile", "result.csv", "输出文件名称(自动设置)")                        // 输出文件名称
	defaultPort      = flag.Int("port", 443, "默认端口")                                               // 端口
	maxThreads       = flag.Int("max", 1000, "并发请求最大协程数")                                          // 最大协程数
	speedTestThreads = flag.Int("speedtest", 5, "下载测速协程数量,设为0禁用测速")                                // 下载测速协程数量
	speedLimit       = flag.Float64("speedlimit", 4, "最低下载速度(MB/s)")                               // 最低下载速度
	speedTestURL     = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	enableTLS        = flag.Bool("tls", true, "是否启用TLS")                                           // TLS是否启用
	multipleNum      = flag.Float64("mulnum", 1, "多协程测速造成测速不准，可进行倍数补偿")                            // speedTest比较大时修改
	tcpLimit         = flag.Int("tcplimit", 1000, "TCP最大延迟(ms)")                                   // TCP最大延迟(ms)
	httpLimit        = flag.Int("httplimit", 1000, "HTTP最大延迟(ms)")                                 // HTTP最大延迟(ms)
	countryCodes     = flag.String("countries", "", "国家代码(US,SG,JP,DE...)，以逗号分隔，留空时检测所有")          // 国家代码数组
	DownloadipLab    = flag.Bool("iplab", false, "为true时检查ip库中的文件并依次下载")                           // 自动下载一些知名的反代IP列表
	Domain           = flag.String("domain", "", "上传地址，默认为空,用Text2KV项目建立的简易文件存储storage.example.com")
	Token            = flag.String("token", "", "上传地址的token，默认为空")
)

var ipLabs = map[string]string{
	"txt.zip":          "https://zip.baipiao.eu.org/",
	"baipiaoge.zip":    "https://zip.baipiao.eu.org/",
	"ip_ProxyIPDB.txt": "https://ipdb.api.030101.xyz/?type=proxy",
	"ip_CFv4IPDB.txt":  "https://ipdb.api.030101.xyz/?type=cfv4",
}

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
)

var (
	requestURL       = "speed.cloudflare.com/cdn-cgi/trace"     // 请求trace URL
	locationsJsonUrl = "https://speed.cloudflare.com/locations" // location.json下载 URL
)

var (
	startTime       = time.Now()        // 标记开始时间
	countries       []string            // 国家代码数组
	locationMap     map[string]location // IP位置数据
	totalIPs        int                 // IP总数
	countProcessed  int                 // 延迟检测已处理进度计数
	countAlive      int                 // 延迟检测存活ip
	percentage      float64             // 检测进度百分比
	totalResultChan []latencyTestResult // 存储延迟测速结果
	countQualified  int                 // 优质ip数量
)

// 延迟检测结果结构体
type latencyTestResult struct {
	ip          string        // IP地址
	port        int           // 端口
	tls         bool          // TLS状态
	dataCenter  string        // 数据中心
	region      string        // 地区
	country     string        // 国家
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

// 下载测速结果结构体
type speedTestResult struct {
	latencyTestResult
	downloadSpeed float64 // 下载速度
}

// 位置信息结构体
type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// IPPort 结构体存储 IP 和端口信息
type IPPort struct {
	IP   string
	Port int
}

var ipPortList []IPPort // 全局变量，存储 IP:port 格式的数据

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
	fmt.Println("正在尝试提升文件描述符的上限...")
	cmd := exec.Command("bash", "-c", "ulimit -n 10000")
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
	} else {
		fmt.Printf("文件描述符上限已提升!\n")
	}
}

// main 主程序
func main() {
	flag.Parse() // 解析命令行参数
	startTime = time.Now()

	osType := runtime.GOOS
	if osType == "linux" {
		increaseMaxOpenFiles()
	}

	// 下载locations.json
	locationsJsonDownload()

	// 网络环境检测，如网络不正常自动退出
	if !autoNetworkDetection() {
		return
	}

	// 存储国家代码到数组中
	if *countryCodes != "" {
		countries = strings.Split(strings.ToUpper(*countryCodes), ",")
	}

	// ipLab列表文件下载及时效性检测
	if *DownloadipLab {
		checked := make(map[string]bool)
		for file, url := range ipLabs {
			if url == "https://zip.baipiao.eu.org/" {
				if !checked[url] {
					fmt.Printf("\033[90m检查 %s\033[0m\n", file)
					checkIPLab(url, file)
					checked[url] = true
				}
			} else {
				fmt.Printf("\033[90m检查 %s\033[0m\n", file)
				checkIPLab(url, file)
			}
		}
		fmt.Printf("\033[32mIP库文件已处于最新状态，请修改\033[0m \033[90m-iplab=false\033[0m \033[32m重新运行程序\033[0m\n")
		os.Exit(0)
	} else {
		lowerFile := strings.ToLower(*File)
		var matchedFile string
		for key := range ipLabs {
			if strings.ToLower(key) == lowerFile {
				matchedFile = key
				break
			}
		}
		if matchedFile != "" {
			*File = matchedFile
			checkIPLab(ipLabs[matchedFile], *File)
		} else if *File == "ip.txt" {
			_, err := os.Stat(*File)
			if os.IsNotExist(err) {
				fmt.Printf("%s 不存在，切换网络IP库 >>>\n", *File)
				*File = "txt.zip"
				ipLaburl := "https://zip.baipiao.eu.org/"
				checkIPLab(ipLaburl, *File)
			}
		} else {
			_, err := os.Stat(*File)
			if os.IsNotExist(err) {
				fmt.Printf("%s 文件不存在，请检查输入！\n", *File)
				os.Exit(0)
			}
		}
	}

	// 设置测速结果文件名
	resetOutFileName()

	if strings.HasSuffix(*File, ".zip") {
		// 获取压缩包文件名
		ZipedFileName := strings.Split(*File, ".")[0]
		caser := cases.Title(language.English)      // 使用English作为默认语言标签
		ZipedFileName = caser.String(ZipedFileName) // 字母小写

		// 生成解压文件文件名
		UnZipedFile := "ip_" + ZipedFileName + "_unZiped.txt"

		fileInfos, err := task.UnZip2txtFile(*File, UnZipedFile)
		if err != nil {
			fmt.Printf("解压文件时出错: %v\n", err)
			return
		}

		if fileInfos != nil {
			// ASN 格式
			processASNZipedFiles(fileInfos)
			// 下载测速并保存结果
			downloadSpeedTest()
		} else {
			// 非 ASN 格式，使用合并后的文件
			task.UnZip2txtFile(*File, UnZipedFile)
			processIPListFile(UnZipedFile)
			// 下载测速并保存结果
			downloadSpeedTest()
		}
	} else {
		// 处理非 ZIP 文件
		processIPListFile(*File)
		// 下载测速并保存结果
		downloadSpeedTest()
	}

	// 更新数据
	reader := bufio.NewReader(os.Stdin)
	switch {
	case *Domain != "" && *Token != "" && countQualified > 0:
		switch strings.ToLower(*File) {
		case "txt.zip", "ip_proxyipdb.txt", "ip_cfv4ipdb.txt", "ip_scanner.txt", "ip_selected.txt", "fofa.zip", "ip_proxyipdb":
			dataUpdate(*outFile, *Domain, *Token)
		default:
			fmt.Printf("\n> 优质ip数量：\033[32m%d\033[0m ,是否要上传数据？(y/n):", countQualified)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(input)
			if input == "y" {
				dataUpdate(*outFile, *Domain, *Token)
			} else {
				fmt.Println("退出程序")
			}
		}
	case (*Domain == "" || *Token == "") && countQualified > 0:
		fmt.Printf("\n> 优质ip数量：\033[32m%d\033[0m ,是否要上传数据？(y/n):", countQualified)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "y" {
			if *Domain == "" {
				fmt.Println("\033[90m请输入Domain（网址）:\033[0m")
				domain, _ := reader.ReadString('\n')
				*Domain = strings.TrimSpace(domain)
			}
			if *Token == "" {
				fmt.Println("\033[90m请输入Token:\033[0m")
				token, _ := reader.ReadString('\n')
				*Token = strings.TrimSpace(token)
			}
			if *Domain != "" && *Token != "" {
				dataUpdate(*outFile, *Domain, *Token)
			} else {
				fmt.Println("\033[31m主机名或token缺失，本次更新取消!\033[0m")
				os.Exit(0)
			}

		} else {
			fmt.Println("退出程序")
		}
	default:
		os.Exit(0)
	}
}

// 功能函数

// 检查location.json文件，如不存在，则从网络下载
func locationsJsonDownload() {
	var locations []location // 创建location数组以存储json文件，
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("正在从 " + locationsJsonUrl + " 下载 locations.json")

		body, err := downloadWithIEProxy(locationsJsonUrl)
		if err != nil {
			fmt.Printf("下载失败: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		file, err := os.Create("locations.json")
		if err != nil {
			fmt.Printf("无法创建文件: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			fmt.Printf("无法写入文件: %v\n", err)
			return
		}
		fmt.Println("\033[32m成功下载并创建 location.json\033[0m")
	} else {
		fmt.Println("\033[0;90m本地 locations.json 已存在,无需重新下载\033[0m")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("无法读取文件: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
	}

	// 读取位置数据并存入变量
	locationMap = make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}
}

// downloadWithIEProxy 尝试使用IE代理设置下载文件
func downloadWithIEProxy(downloadURL string) ([]byte, error) {
	proxyFunc := ieproxy.GetProxyFunc()
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: proxyFunc},
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("下载时出错: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) // 尝试读取响应体以获取更多错误信息
		return nil, fmt.Errorf("非预期的HTTP状态码: %v, 响应体: %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// autoNetworkDetection 自动检测网络环境，返回一个bool值
func autoNetworkDetection() bool {
	// 检查系统代理是否启用
	if checkProxyEnabled() {
		fmt.Println("\033[2J\033[0;0H\033[31m检测到系统代理已启用，请关闭VPN后重试。\033[0m")
		return false
	} else {
		fmt.Println("\033[90m系统代理未启用，检测tun模式代理……\033[0m")

		// 检查Google.com是否可访问
		if checkProxyUrl("https://www.google.com") {
			fmt.Println("\033[31m已开启tun模式代理，可以访问外网，请关闭VPN后重试。\033[0m")
			return false
		} else {
			fmt.Println("\033[90m未开启vpn，检测墙内网络是否正常……\033[0m")
		}
	}

	// 检测Baidu是否可访问
	if !checkNormalUrl("https://www.baidu.com") {
		fmt.Println("\033[2J\033[0;0H\033[31m无互联网访问，请检查网络连接。\033[0m")
		return false
	} else {
		// 清除输出内容
		fmt.Print("\033[2J\033[0;0H")
		fmt.Printf("\033[32m网络环境检测正常 \033[0m\n")
	}
	return true
}

// checkProxyEnabled 检测是否开启系统代理服务器
func checkProxyEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		fmt.Println("无法打开注册表键:", err)
	}
	defer k.Close()

	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		fmt.Println("无法读取ProxyEnable值:", err)
		return false
	}

	return proxyEnable == 1 // proxyEnable键值若为1，说明开启了代理服务器，返回true
}

// checkNormalUrl 尝试连接指定的URL，检查网络是否可访问
func checkNormalUrl(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		// fmt.Printf("访问 %s 时未知错误:[ %v ]\n", url, err)
		return false
	}
	defer resp.Body.Close()
	// fmt.Println("检测可以ping通:" + url)
	return true
}

// checkProxyUrl 根据域名检测连通性，自动检测代理服务器.
func checkProxyUrl(urlStr string) bool {
	proxyFunc := ieproxy.GetProxyFunc()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: proxyFunc},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		// fmt.Printf("连通性错误 %s: %v\n", urlStr, err)
		return false
	}
	defer resp.Body.Close()

	// fmt.Println("成功连接: " + urlStr)
	return true
}

// 检查IP库是否存在并执行下载
func checkIPLab(url string, fileName string) {
	fileInfo, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		// 文件不存在，直接下载
		fmt.Printf("\033[31mip库文件 %s 不存在，正在下载...\033[0m\n", fileName)
		downloadFile(url, fileName)
	} else {
		// 文件存在，检查创建时间
		fileModTime := fileInfo.ModTime()
		if time.Since(fileModTime) > 12*time.Hour {
			// 文件超过12小时，重新下载
			fmt.Printf("\033[31mip库文件 %s 超过12小时，正在重新下载...\033[0m\n", fileName)
			downloadFile(url, fileName)
		} else {
			// fmt.Printf("ip库文件 %s 存在且未超过12小时，无需下载\n",fileName)
		}
	}
}

// 文件下载函数
func downloadFile(url, fileName string) {
	// 创建文件
	out, err := os.Create(fileName)
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return
	}
	defer out.Close()

	// 获取数据
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("下载失败:", err)
		return
	}
	defer resp.Body.Close()

	// 写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		fmt.Println("写入文件失败:", err)
	}
	fmt.Println("下载状态...........................................[\033[32mok\033[0m]\n")
}

// 测速结果输出文件重命名函数
func resetOutFileName() {
	if strings.Contains(*File, "_") {
		FileName := strings.Split(*File, ".")[0]      // 去掉后缀名
		resultName := strings.Split(FileName, "_")[1] // 分离名字字段
		caser := cases.Title(language.English)        // 使用English作为默认语言标签
		resultName = caser.String(resultName)         // 首字母大写

		if *outFile == "result.csv" {
			// 如果输出文件名为默认，即未指定
			*outFile = "result_" + resultName + ".csv"
		}

	} else if *File == "txt.zip" {
		// 默认反代IP列表
		if *outFile == "result.csv" {
			*outFile = "result_Baipiaoge.csv"
		}
	} else if *File == "ip.txt" {
		// 默认ip列表
		if *outFile == "result.csv" {
			*outFile = "result_Test.csv"
		}
	} else {
		FileName := strings.Split(*File, ".")[0] // 去掉后缀名
		caser := cases.Title(language.English)   // 使用English作为默认语言标签
		FileName = caser.String(FileName)        // 首字母大写

		if *outFile == "result.csv" {
			*outFile = "result_" + FileName + ".csv"
		}
	}
}

// 处理文件格式为“ASN-Tls-Port.txt”格式的压缩包文件
func processASNZipedFiles(fileInfos []task.FileInfo) {
	totalAliveIPs := 0
	totalIPs = 0
	for _, info := range fileInfos {
		ips := strings.Split(string(info.Content), "\n")
		totalIPs += len(ips)
	}

	for _, info := range fileInfos {
		// 直接使用 info.Content 处理 IP 列表
		ips := strings.Split(string(info.Content), "\n")

		// 使用集合去重
		ipSet := make(map[string]struct{})
		for _, ip := range ips {
			if ip != "" {
				ipSet[ip] = struct{}{}
			}
		}
		// 将集合转换回切片
		uniqueIPs := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			uniqueIPs = append(uniqueIPs, ip)
		}

		aliveCount := delayedDetectionIPs(uniqueIPs, info.TLS, info.Port)
		totalAliveIPs += aliveCount
	}

	if len(totalResultChan) == 0 {
		fmt.Println("\033[31m没有发现有效的IP\033[0m                                               ")
		os.Exit(0)
	}
}

// 处理单个ip列表，txt格式
func processIPListFile(fileName string) {
	totalAliveIPs := 0

	ips, err := readIPs(fileName)
	if err != nil {
		fmt.Printf("读取 IP 时出错: %v\n", err)
		return
	}

	totalIPs = len(ips) + len(ipPortList) // 总ip数，包括单行ip和带端口ip数
	if totalIPs == 0 {
		// 未读取ip退出程序
		fmt.Println("\033[31m未读取到IP数据\033[0m                                               ")
		os.Exit(0)
	} else if len(ipPortList) == 0 {
		// 如果带端口ip数为0,则直接检测单行ip数组
		aliveCount := delayedDetectionIPs(ips, *enableTLS, *defaultPort)
		totalAliveIPs += aliveCount
	} else {
		for _, ip := range ips {
			// 混杂的情况，把单行ip加上默认端口添加到ipPortList数组中统一处理
			ipPortList = append(ipPortList, IPPort{ip, *defaultPort})
		}
		for _, ipPort := range ipPortList {
			// 将 ipPort.IP 转换为 []string
			ipsNew := []string{ipPort.IP}
			aliveCount := delayedDetectionIPs(ipsNew, *enableTLS, ipPort.Port)
			totalAliveIPs += aliveCount
		}
	}

	if len(totalResultChan) == 0 {
		fmt.Println("\033[31m没有发现有效的IP\033[0m                                               ")
		os.Exit(0)
	}
}

// ip延迟检测函数
func delayedDetectionIPs(ips []string, enableTLS bool, port int) int {
	var wg sync.WaitGroup
	wg.Add(len(ips))

	// 创建一个长度为输入数据长度的通道
	resultChan := make(chan latencyTestResult, len(ips))

	thread := make(chan struct{}, *maxThreads)
	total := totalIPs // ip数据总数

	for _, ip := range ips {
		countProcessed++ // 已处理ip数计数器
		percentage = float64(countProcessed) / float64(total) * 100

		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()

				// 并发检测进度显示
				fmt.Printf(":已检测: %d 总数: %d 进度: %.2f%%  存活ip: \033[1;32m\033[5m%d\033[0m            \r", countProcessed, total, percentage, countAlive)
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()

			// 使用新的DialContext函数,这里context.Background()提供了一个空的上下文
			conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					// 使用新的DialContext函数
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: timeout,
			}

			var protocol string
			if enableTLS {
				protocol = "https://"
			} else {
				protocol = "http://"
			}
			requestURL := protocol + requestURL
			req, _ := http.NewRequest("GET", requestURL, nil)

			// 添加用户代理
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			duration := time.Since(start)
			if duration > maxDuration {
				return
			}

			buf := &bytes.Buffer{}
			body := buf // 将body声明移动到这里
			// 创建一个读取操作的超时
			timeout := time.After(maxDuration)
			// 使用一个 goroutine 来读取响应体
			done := make(chan bool)
			go func() {
				_, copyErr := io.Copy(buf, resp.Body)
				done <- true
				if copyErr != nil {
					// fmt.Printf("读取响应体错误: %v", copyErr)
					return
				}
			}()
			// 等待读取操作完成或者超时
			select {
			case <-done:
				// 读取操作完成
			case <-timeout:
				// 读取操作超时
				return
			}

			if strings.Contains(body.String(), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]

					// 根据tcp和http延迟筛选检测结果
					if float64(tcpDuration.Milliseconds()) <= float64(*tcpLimit) && float64(duration.Milliseconds()) <= float64(*httpLimit) {
						// 根据国家代码筛选检测结果，如果为空，则不筛选
						if len(countries) == 0 || containsIgnoreCase(countries, loc.Cca2) {
							countAlive++ // 记录存活IP数量
							if ok {
								fmt.Printf("-有效IP %s 端口 %d 位置:%s.%s 延迟 %d ms          \n", ip, port, loc.City, loc.Cca2, duration.Milliseconds())

								resultChan <- latencyTestResult{ip, port, enableTLS, dataCenter, loc.Region, loc.Cca2, loc.City, fmt.Sprintf("%d", duration.Milliseconds()), tcpDuration}
							} else {
								fmt.Printf("-有效IP %s 端口 %d 位置信息未知 延迟 %d ms             \n", ip, port, tcpDuration.Milliseconds())

								resultChan <- latencyTestResult{ip, port, enableTLS, dataCenter, "", "", "", fmt.Sprintf("%d", duration.Milliseconds()), tcpDuration}
							}
						}
					}
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	// 把通道里的内容添加到全局变量totalResultChan数组中，以便统一处理，增加效率
	for res := range resultChan {
		totalResultChan = append(totalResultChan, res)
	}

	// 并发检测执行完毕后输出信息
	if countProcessed == total {
		fmt.Printf(":已检测: %d 总数: %d 进度: \033[32m%.2f%%\033[0m  存活ip:  \033[1;32m\033[5m%d\033[0m            \r", countProcessed, total, percentage, countAlive)
		fmt.Printf("\nTCP/HTTP延迟检测完成！\n")
	}
	return countAlive
}

// 从文件中读取IP地址并处理
func readIPs(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 创建一个 map 存储不重复的 IP 地址
	ipMap := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddr := scanner.Text()
		// 判断是否为 CIDR 格式的 IP 地址
		if strings.Contains(ipAddr, "/") && strings.Count(ipAddr, ":") != 1 && strings.Count(ipAddr, "#") != 1 {
			ip, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				fmt.Printf("无法解析CIDR格式的IP: %v\n", err)
				continue
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				ipMap[ip.String()] = struct{}{}
			}
		} else if strings.Contains(ipAddr, ":") || strings.Contains(ipAddr, "#") {
			if strings.Count(ipAddr, ":") > 1 {
				// IPv6 地址
				ipMap[ipAddr] = struct{}{}
			} else if strings.Count(ipAddr, ":") == 1 {
				// 带端口的IP列表，以:分割ip与port，IP:port 格式
				if strings.Contains(ipAddr, "#") {
					ipPort := strings.Split(ipAddr, "#")[0]
					ip := strings.Split(ipPort, ":")[0]
					portStr := strings.Split(ipPort, ":")[1]
					port, err := strconv.Atoi(portStr)
					if err != nil {
						fmt.Println("端口转换错误:", err)
						continue
					}
					// ipMap[ip] = struct{}{}
					ipPortList = append(ipPortList, IPPort{IP: ip, Port: port}) // 存储 IP:port 格式的数据
				} else {
					ip := strings.Split(ipAddr, ":")[0]
					portStr := strings.Split(ipAddr, ":")[1]
					port, err := strconv.Atoi(portStr)
					if err != nil {
						fmt.Println("端口转换错误:", err)
						continue
					}
					// ipMap[ip] = struct{}{}
					ipPortList = append(ipPortList, IPPort{IP: ip, Port: port}) // 存储 IP:port 格式的数据
				}
			}
		} else {
			ipMap[ipAddr] = struct{}{}
		}
	}

	// 将 map 的键转换回切片，获得去重的ip地址
	ips := make([]string, 0, len(ipMap))
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	fmt.Println("\n成功获取去重ip列表，开始TCP/HTTP延迟检测...")

	return ips, scanner.Err()
}

// inc函数实现ip地址自增
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 下载测速函数
func getDownloadSpeed(ip string, port int, enableTLS bool) float64 {
	var protocol string

	if enableTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}

	speedTestURL := protocol + *speedTestURL
	// 创建请求
	req, _ := http.NewRequest("GET", speedTestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	// 创建TCP连接
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0
	}
	defer conn.Close()

	// 标记时间点
	startTime_duration := time.Now()
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			// 使用新的DialContext函数
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		// 外网访问延迟较大，设置单个IP延迟最长时间为5秒
		Timeout: 5 * time.Second,
	}

	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("-IP %s 端口 %s \033[9;31m测速无效\033[0m                                 \n", ip, strconv.Itoa(port))
		return 0
	}
	defer resp.Body.Close()

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime_duration)

	// speed_KB := float64(written) / duration.Seconds() / 1024  //单位KB/s
	speedOrignal := float64(written) / duration.Seconds() / (1024 * 1024) // 真实测速数据，如开多协程会有失真。单位MB/s

	if *multipleNum == 1 || *speedTestThreads < 5 {
		speed := float64(written) / duration.Seconds() / (1024 * 1024)
		// 输出结果
		fmt.Printf("-IP %s 端口 %s 下载速度 %.1f MB/s        \n", ip, strconv.Itoa(port), speed)
		return speed
	} else {
		// 多协程测速会有速度损失，加以补偿
		speed := float64(written) / duration.Seconds() / (1024 * 1024) * (*multipleNum)
		fmt.Printf("-IP %s 端口 %s 下载速度 %.1f MB/s, 补偿系数 %.0f × %.1f MB/s\n", ip, strconv.Itoa(port), speed, *multipleNum, speedOrignal)
		return speed
	}
}

// 并发下载测速函数
func downloadSpeedTest() {
	var results []speedTestResult

	if *speedTestThreads > 0 {
		fmt.Printf("\n\n开始下载测速\n")
		if *speedTestThreads > 5 && *multipleNum == 1 {
			fmt.Printf("\033[90m> 即将建立\033[0m \033[31m%d\033[0m \033[90m个并发协程，测速可能失真。建议增加\033[0m\033[4;33m %d \033[0m\033[90m倍补偿系数\033[0m\n", *speedTestThreads, *speedTestThreads/5)

			// 创建一个新的读数器
			reader := bufio.NewReader(os.Stdin)
			// for 循环检测用户输入
			for {
				// 获取用户输入
				fmt.Print("  请输入补偿系数（默认为1）：")
				input, err := reader.ReadString('\n')
				if err != nil {
					fmt.Println("\033[31m  无法读取输入:\033[0m", err)
					os.Exit(1)
				}

				// 去除输入字符串前后的空白字符
				input = strings.TrimSpace(input)

				// 将用户输入转换为浮点数
				if input != "" {
					*multipleNum, err = strconv.ParseFloat(input, 64)
					if err != nil {
						fmt.Println("\033[31m  请输入一个有效的数字\033[0m")
						*multipleNum = 1 // 补偿系数恢复初始值
						continue
					}
				}
				break
			}
			// 在这里使用multipleNum进行计算或其他操作
			fmt.Printf("\n\033[90m> 并发测速补偿系数已设置为\033[0m \033[32m%.1f\033[0m\n\n", *multipleNum)
		}

		var wg sync.WaitGroup
		var countSt int32 = 0 // 下载测速进度计数器
		var mu sync.Mutex     // 同步锁
		thread := make(chan struct{}, *speedTestThreads)
		total := len(totalResultChan)

		for id, res := range totalResultChan {
			wg.Add(1)
			thread <- struct{}{}
			go func(id int, res latencyTestResult) {
				defer func() {
					<-thread
					wg.Done()
					// 测速进程运行完成
					if atomic.LoadInt32(&countSt) == int32(total) {
						fmt.Printf("下载测速进度已完成 \033[1;32m%.2f%%\033[0m                                \r", 100.0)
					}
				}()

				// 记录下载测速进度
				atomic.AddInt32(&countSt, 1)
				percentage := float64(countSt) / float64(total) * 100

				downloadSpeed := getDownloadSpeed(res.ip, res.port, res.tls)
				mu.Lock()
				results = append(results, speedTestResult{latencyTestResult: res, downloadSpeed: downloadSpeed})
				mu.Unlock()
				fmt.Printf("协程 \033[33m%d\033[0m 正在检测 %s  总进度 \033[1;32m%.2f%%\033[0m                   \r", id+1, res.ip, percentage)
			}(id, res)
		}
		wg.Wait()

	} else {
		for _, res := range totalResultChan {
			results = append(results, speedTestResult{latencyTestResult: res})
		}
	}
	if *speedTestThreads > 0 {
		sort.Slice(results, func(i, j int) bool {
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
	} else {
		sort.Slice(results, func(i, j int) bool {
			return results[i].latencyTestResult.tcpDuration < results[j].latencyTestResult.tcpDuration
		})
	}

	// 下载测速结果写入文件
	writeResults(results)
}

// writeResults 写入文件函数
func writeResults(results []speedTestResult) {
	// 放到外面以便调用
	countQualified = 0 // 下载速度达标ip 计数器
	countSpeed := 0    // 下载速度大于0 计数器
	if *speedTestThreads > 0 {
		for _, res := range results {
			if res.downloadSpeed >= float64(*speedLimit) {
				countQualified++
			}
			if res.downloadSpeed > 0 {
				countSpeed++
			}
		}
	}
	if countSpeed == 0 {
		fmt.Println("\033[31m下载测速无可用IP\033[0m                                               ")
		os.Exit(0)
	}
	// 达标的测速ip输出到一个文件
	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()
	file.WriteString("\xEF\xBB\xBF") // 标记为utf-8 bom编码,防止excel打开中文乱码

	// 未达标的测速ip输出到一个文件
	outFileUnqualified := "result_Unqualified.csv"
	fileUnqualified, err := os.Create(outFileUnqualified)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer fileUnqualified.Close()
	fileUnqualified.WriteString("\xEF\xBB\xBF") // 标记为utf-8 bom编码,防止excel打开中文乱码

	writer := csv.NewWriter(file)
	writerUnqualified := csv.NewWriter(fileUnqualified)

	if *speedTestThreads > 0 {
		if countQualified > 0 {
			writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "国家", "城市", "延迟(ms)", "下载速度(MB/s)"})
		}
		writerUnqualified.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "国家", "城市", "延迟(ms)", "下载速度(MB/s)"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "国家", "城市", "延迟(ms)"})
		writerUnqualified.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "国家", "城市", "延迟(ms)"})
	}
	// fmt.Printf("\n")
	if countQualified > 0 {
		fmt.Printf("\n\n优选ip,下载速度高于 \033[32m%.1f\033[0m MB/s，测速结果：\n", *speedLimit)
	}
	for _, res := range results {
		if *speedTestThreads > 0 {
			if res.downloadSpeed >= float64(*speedLimit) && countQualified > 0 {
				// 根据设定限速值，测速结果写入不同文件
				writer.Write([]string{res.latencyTestResult.ip, strconv.Itoa(res.latencyTestResult.port), strconv.FormatBool(*enableTLS), res.latencyTestResult.dataCenter, res.latencyTestResult.region, res.latencyTestResult.country, res.latencyTestResult.city, res.latencyTestResult.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})

				// 终端输出优选结果
				fmt.Printf("%s:%d#%s-%.1f MB/s\n", res.latencyTestResult.ip, res.latencyTestResult.port, res.latencyTestResult.country, res.downloadSpeed)

			} else {
				writerUnqualified.Write([]string{res.latencyTestResult.ip, strconv.Itoa(res.latencyTestResult.port), strconv.FormatBool(*enableTLS), res.latencyTestResult.dataCenter, res.latencyTestResult.region, res.latencyTestResult.country, res.latencyTestResult.city, res.latencyTestResult.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})
			}
		} else {
			writer.Write([]string{res.latencyTestResult.ip, strconv.Itoa(res.latencyTestResult.port), strconv.FormatBool(*enableTLS), res.latencyTestResult.dataCenter, res.latencyTestResult.region, res.latencyTestResult.country, res.latencyTestResult.city, res.latencyTestResult.latency})
			writerUnqualified.Write([]string{res.latencyTestResult.ip, strconv.Itoa(res.latencyTestResult.port), strconv.FormatBool(*enableTLS), res.latencyTestResult.dataCenter, res.latencyTestResult.region, res.latencyTestResult.country, res.latencyTestResult.city, res.latencyTestResult.latency})

		}
	}

	writer.Flush()
	writerUnqualified.Flush()
	// 清除输出内容
	// fmt.Print("\033[2J")
	if countQualified > 0 {
		fmt.Printf("\n\033[32m>\033[0m 优质ip写入 \033[90;4m%s\033[0m 耗时 %d 秒\n", *outFile, time.Since(startTime)/time.Second)
	} else {
		fmt.Printf("\n\n未发现下载速度高于 \033[31m%.1f\033[0m MB/s的IP，但存在可用低速IP\n", *speedLimit)
	}

	fmt.Printf("\033[31m>\033[0m 低速ip写入 \033[4;90m%s\033[0m 耗时 %d 秒\n", outFileUnqualified, time.Since(startTime)/time.Second)
}

// 忽略大小写的对比函数
func containsIgnoreCase(slice []string, item string) bool {
	item = strings.ToUpper(item)
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
