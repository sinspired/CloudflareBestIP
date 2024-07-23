package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// IPInfo 用于存储从API返回的IP信息
type IPInfo struct {
	IP       string       `json:"ip"`
	Company  CompanyInfo  `json:"company"`
	ASN      ASNInfo      `json:"asn"`
	Location LocationInfo `json:"location"`
}

// CompanyInfo 用于存储公司信息
type CompanyInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// ASNInfo 用于存储ASN信息
type ASNInfo struct {
	ASN     int    `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country"`
	Type    string `json:"type"`
}

// LocationInfo 用于存储位置信息
type LocationInfo struct {
	Country_code string `json:"country_code"`
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

const (
	requestURL       = "https://speed.cloudflare.com/cdn-cgi/trace" // 请求trace URL
	locationsJsonUrl = "https://speed.cloudflare.com/locations"     // location.json下载 URL
)

var locationMap map[string]location // IP位置数据
// 读取机场信息
func readLocationData() {
	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("正在从 " + locationsJsonUrl + " 下载 locations.json")

		resp, err := http.Get(locationsJsonUrl)
		if err != nil {
			fmt.Printf("下载失败: %v\n", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("无法读取响应体: %v\n", err)
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
		// 读取位置数据并存入变量
		locationMap = make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}
		// fmt.Println("读取到 loacations 机场位置数据")
	}
}

// 从文件中读取IP地址并处理
func readIPResults(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer file.Close()

	var ipPortWithTag []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddr := scanner.Text()
		if len(ipAddr) < 7 {
			continue
		}
		ipPort := strings.Split(ipAddr, "#")[0]
		ipTag := strings.Split(ipAddr, "丨")[1]
		ipPortWithTag = append(ipPortWithTag, ipPort+"丨"+ipTag)
	}

	return ipPortWithTag, scanner.Err()
}

// 查询IP信息并返回其类型（住宅、商务、专线或其他）
func getIPInfo(ip, apiKey string) (IPInfo, error) {
	var url string
	if apiKey != "" {
		url = fmt.Sprintf("https://api.ipapi.is?q=%s&key=%s", ip, apiKey)
	} else {
		fmt.Printf("\r使用免费接口，如检测量大请自行提供apiKey\r")
		url = fmt.Sprintf("https://api.ipapi.is/?ip=%s", ip)
	}

	// 创建一个自定义的 http.Client，并设置超时时间
	client := http.Client{
		Timeout: 50 * time.Second, // 设置超时时间为10秒
	}

	// 使用自定义的 client 发送 GET 请求
	resp, err := client.Get(url)
	if err != nil {
		fmt.Print("x")
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Print("x")
		return IPInfo{}, err
	}

	var ipInfo IPInfo
	err = json.Unmarshal(body, &ipInfo)
	if err != nil {
		fmt.Print("x")
		return IPInfo{}, err
	}
	// fmt.Print(".")
	return ipInfo, err
}

// 为 IPInfo 结构体创建 getIPType 方法
func (info *IPInfo) getIPType() (string, error) {
	if info.Company.Type == "isp" {
		switch info.ASN.Type {
		case "isp":
			return "住宅", nil
		case "business":
			return "家宽", nil
		case "hosting":
			return "托管", nil
		default:
			return info.ASN.Type, nil
		}
	} else if info.Company.Type == "business" {
		switch info.ASN.Type {
		case "isp":
			return "商宽", nil
		case "business":
			return "商务", nil
		case "hosting":
			return "VPS", nil
		default:
			return info.ASN.Type, nil
		}
	} else if info.Company.Type == "hosting" {
		switch info.ASN.Type {
		case "isp":
			return "中转", nil
		case "business":
			return "商管", nil
		case "hosting":
			return "机房", nil
		default:
			return "行业机房", nil
		}
	} else {
		return info.ASN.Type, nil
	}
}

// 原生ip还是广播ip
func (info *IPInfo) isUniIP() bool {
	asnCountry := strings.ToUpper(info.ASN.Country)
	locCountry := strings.ToUpper(info.Location.Country_code)
	if asnCountry == locCountry {
		return true
	}
	return false
}

// Asn组织名称缩写
func (info *IPInfo) getOrgNameAbbr() string {
	mappings := map[string]string{
		"sk broadband": "SKB",
		"cmb":          "CMB",
		"taegu":        "CMB",
		"spectrum":     "CFS",
		"cloudflare":   "CF",
		"bigcommerce":  "BigC",
		"tcloudnet":    "TCN",
		"amazon":       "AWS",
		"linked":       "Lin",
		"porsche":      "Porsche",
		"tencent":      "Tencent",
		"alibaba":      "ALi",
		"oracle":       "Oracle",
		"powercomm":    "LG",
		"powervis":     "LG",
		"zdm network":  "ZDM",
		"cogent":       "Cog",
		"kirino":       "Kirino",
		"microsoft":    "Microsoft",
		"it7":          "IT7",
		"cluster":      "Cluster",
		"m247":         "M247",
		"multacom":     "MUL",
		"dimt":         "DMIT",
		"chunghwa":     "CHT",
		"pittqiao":     "PIQ",
	}
	org := info.ASN.Org
	for key, value := range mappings {
		if strings.Contains(strings.ToLower(org), key) {
			return value
		}
	}

	if len(org) > 5 {
		return strings.ToUpper(org[:3])
	}
	return strings.ToUpper(org)
}


func reParseResultTxtFile(ipFile string, apiKey string) {
	// 定义命令行参数
	flag.Parse()
	args := flag.Args()
	// ip := "8.8.8.8"      // 替换为要查询的IP地址

	if len(args) > 0 {
		ipFile = args[0]
	}

	if ipFile == "" {
		ipFile = "ip-AI.txt"
	}

	ipPortWithTag, err := readIPResults(ipFile)
	if err != nil {
		return
	}
	type Result struct {
		index int
		line  string
	}

	results := make(chan Result, len(ipPortWithTag))

	var wg sync.WaitGroup
	fmt.Println("\033[90m正在获取ip信息并处理，请稍等！\033[0m")

	for i, ipPortWithTag := range ipPortWithTag {
		wg.Add(1)
		go func(index int, ipPortWithTag string) {
			defer func() {
				wg.Done()
				fmt.Print(".")
			}()

			ipPort := strings.Split(ipPortWithTag, "丨")[0]
			tag := strings.Split(ipPortWithTag, "丨")[1]
			ip := strings.Split(ipPort, ":")[0]
			port := strings.Split(ipPort, ":")[1]
			dataCenterCoCo := checkDataCenterCoco(ip, port)

			info, err := getIPInfo(ip, apiKey)
			if err != nil {
				results <- Result{index, fmt.Sprintf("获取ip信息错误 %s: %v", ip, err)}
				return
			}

			ipType, err := info.getIPType()
			if err != nil {
				results <- Result{index, fmt.Sprintf("获取ip类型错误 %s: %v", ip, err)}
				return
			}

			var uniIPStatus string
			if info.isUniIP() {
				uniIPStatus = "Uni"
			} else {
				uniIPStatus = "Bro"
			}

			// 根据数据中心地址和ip位置是否相同，设置显示信息
			var ipLocation string
			var cnProxy string
			ipCoCo := info.Location.Country_code

			ipLocation = ipCoCo
			if ipCoCo == dataCenterCoCo {
				ipLocation = ipCoCo
			} else if dataCenterCoCo != "" {
				ipLocation = ipCoCo + "-" + dataCenterCoCo
				if ipCoCo == "CN" {
					cnProxy = "中转"
				}
			}

			org := info.getOrgNameAbbr()
			line := fmt.Sprintf("%s:%s#%s-%s%s%s-%s-%d丨%s", ip, port, ipLocation, uniIPStatus, ipType, cnProxy, org, info.ASN.ASN, tag)

			results <- Result{index, line}
		}(i, ipPortWithTag)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	resultSlice := make([]string, len(ipPortWithTag))
	for result := range results {
		resultSlice[result.index] = result.line
	}

	// 按顺序输出结果
	fmt.Println("\n\033[32m解析完成！\033[0m")
	fmt.Println("+--------------------------------------------------------+")
	for _, line := range resultSlice {
		fmt.Println(line)
	}
	fmt.Println("+--------------------------------------------------------+")
}


func checkDataCenterCoco(ip string, port string) string {
	client := http.Client{
		Transport: &http.Transport{
			// 使用 DialContext 函数
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 阻止重定向
		},
		Timeout: 30 * time.Second,
	}

	req, _ := http.NewRequest(http.MethodHead, requestURL, nil)

	// 添加用户代理
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Print("x")
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Print("x")
		return ""
	}

	// 获取机场三字码，数据中心位置
	var colo string
	if resp.Header.Get("Server") == "cloudflare" {
		str := resp.Header.Get("CF-RAY") // 示例 cf-ray: 7bd32409eda7b020-SJC
		colo = regexp.MustCompile(`[A-Z]{3}`).FindString(str)
	} else {
		str := resp.Header.Get("x-amz-cf-pop") // 示例 X-Amz-Cf-Pop: SIN52-P1
		colo = regexp.MustCompile(`[A-Z]{3}`).FindString(str)
	}

	loc, ok := locationMap[colo]
	if ok {
		// fmt.Print(".")
		return loc.Cca2
	}
	fmt.Print("x")
	return "未获取数据"
}

// 检测当前apiKey是否达到上限
func isApiKeyNotExceed(apiKey string) bool {
	url := fmt.Sprintf("https://api.ipapi.is?q=%s&key=%s", "8.8.8.8", apiKey)

	// 创建一个自定义的 http.Client，并设置超时时间
	client := http.Client{
		Timeout: 50 * time.Second, // 设置超时时间为10秒
	}

	// 使用自定义的 client 发送 GET 请求
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("连接错误：%v\n", err)
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Print("无法读取")
		return false
	}
	// fmt.Println(string(body))
	if strings.Contains(string(body), "exceeded") {
		fmt.Println("达到限额")
		return false
	}
	return true
}

func main() {
	apiKey := "" // 替换为你的API密钥
	// // apiKey := ""
	// if isApiKeyNotExceed(apiKey) {
	// 	apiKey = ""
	// } else {
	// 	apiKey = ""
	// }
	readLocationData()
	fmt.Print("\033[2J\033[0;0H") // 清空屏幕
	reParseResultTxtFile("", apiKey)
}
