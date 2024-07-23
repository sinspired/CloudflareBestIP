package task

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// getIPInfo 查询IP信息并返回其类型（住宅、商务、专线或其他）
func GetIPInfo(ip, apiKey string) (IPInfo, error) {
	var url string
	if apiKey != "" {
		url = fmt.Sprintf("https://api.ipapi.is?q=%s&key=%s", ip, apiKey)
	} else {
		fmt.Println("使用免费接口，如检测量大请自行提供apiKey\r")
		url = fmt.Sprintf("https://api.ipapi.is/?ip=%s", ip)
	}

	// 创建一个自定义的 http.Client，并设置超时时间
	client := http.Client{
		Timeout: 50 * time.Second, // 设置超时时间为10秒
	}

	// 使用自定义的 client 发送 GET 请求
	resp, err := client.Get(url)
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return IPInfo{}, err
	}

	var ipInfo IPInfo
	err = json.Unmarshal(body, &ipInfo)
	if err != nil {
		return IPInfo{}, err
	}
	return ipInfo, err
}

// 为 IPInfo 结构体创建 getIPType 方法
func (info *IPInfo) GetIPType() (string, error) {
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
func (info *IPInfo) IsUniIP() bool {
	asnCountry := strings.ToUpper(info.ASN.Country)
	locCountry := strings.ToUpper(info.Location.Country_code)
	if asnCountry == locCountry {
		return true
	}
	return false
}

// Asn组织名称缩写
func (info *IPInfo) GetOrgNameAbbr() string {
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

// 检测当前apiKey是否达到上限
func IsApiKeyNotExceed(apiKey string) bool {
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
		fmt.Println("ip-API达到限额")
		return false
	}
	return true
}