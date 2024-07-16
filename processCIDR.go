package main

import (
	"bufio" // 用于读取文件
	// "fmt"
	"log"       // 用于日志记录
	"math/rand" // 用于生成随机数
	"net"       // 用于IP地址和网络相关操作
	"os"        // 用于文件操作
	"strings"   // 用于字符串操作
	"time"      // 用于时间相关操作
)

const defaultInputFile = "ip.txt"

var (
	// TestAll 表示是否测试所有IP
	TestAll = false
	// IPFile 是包含IP范围的文件名
	IPFile = defaultInputFile
	IPText string
)

// InitRandSeed 初始化随机数种子
func InitRandSeed() {
	rand.Seed(time.Now().UnixNano())
}

// isIPv4 检查给定的IP是否为IPv4
func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

// randIPEndWith 生成一个在给定范围内的随机字节值
func randIPEndWith(num byte) byte {
	if num == 0 { // 对于 /32 或 /128 这种单独的IP
		return byte(0)
	}
	return byte(rand.Intn(int(num)))
}

// IPRanges 表示一组IP地址范围的结构体
type IPRanges struct {
	ips     []*net.IPAddr // 存储生成的IP地址
	mask    string        // 子网掩码
	firstIP net.IP        // 起始IP地址
	ipNet   *net.IPNet    // IP网络
}

// newIPRanges 创建一个新的IPRanges实例
func newIPRanges() *IPRanges {
	return &IPRanges{
		ips: make([]*net.IPAddr, 0),
	}
}

// fixIP 如果是单独的IP，则添加子网掩码
func (r *IPRanges) fixIP(ip string) string {
	if i := strings.IndexByte(ip, '/'); i < 0 {
		if isIPv4(ip) {
			r.mask = "/32"
		} else {
			r.mask = "/128"
		}
		ip += r.mask
	} else {
		r.mask = ip[i:]
	}
	return ip
}

// parseCIDR 解析CIDR格式的IP范围
func (r *IPRanges) parseCIDR(ip string) {
	var err error
	if r.firstIP, r.ipNet, err = net.ParseCIDR(r.fixIP(ip)); err != nil {
		log.Fatalln("ParseCIDR error:", err)
	}
}

// appendIPv4 将IPv4地址添加到列表中
func (r *IPRanges) appendIPv4(d byte) {
	r.appendIP(net.IPv4(r.firstIP[12], r.firstIP[13], r.firstIP[14], d))
}

// appendIP 将IP地址添加到列表中
func (r *IPRanges) appendIP(ip net.IP) {
	r.ips = append(r.ips, &net.IPAddr{IP: ip})
}

// getIPRange 返回第四段IP的最小值及可用数目
func (r *IPRanges) getIPRange() (minIP, hosts byte) {
	minIP = r.firstIP[15] & r.ipNet.Mask[3] // IP第四段最小值

	// 计算主机数量
	m := net.IPv4Mask(255, 255, 255, 255)
	for i, v := range r.ipNet.Mask {
		m[i] ^= v
	}
	total := int(m[3]) + 1 // 总可用IP数
	if total > 255 {       // 矫正第四段可用IP数
		hosts = 255
		return
	}
	hosts = byte(total)
	return
}

// chooseIPv4 生成CIDR范围内的随机IPv4地址
func (r *IPRanges) chooseIPv4() {
	if r.mask == "/32" { // 单个IP则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		minIP, hosts := r.getIPRange()    // 返回第四段IP的最小值及可用数目
		for r.ipNet.Contains(r.firstIP) { // 只要该IP没有超出IP网段范围，就继续循环随机
			if TestAll { // 如果是测试全部IP
				for i := 0; i <= int(hosts); i++ { // 遍历IP最后一段最小值到最大值
					r.appendIPv4(byte(i) + minIP)
				}
			} else { // 随机IP的最后一段0.0.0.X
				r.appendIPv4(minIP + randIPEndWith(hosts))
			}
			r.firstIP[14]++ // 0.0.(X+1).X
			if r.firstIP[14] == 0 {
				r.firstIP[13]++ // 0.(X+1).X.X
				if r.firstIP[13] == 0 {
					r.firstIP[12]++ // (X+1).X.X.X
				}
			}
		}
	}
}

// chooseIPv6 生成CIDR范围内的随机IPv6地址
func (r *IPRanges) chooseIPv6() {
	if r.mask == "/128" { // 单个IP则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		for r.ipNet.Contains(r.firstIP) { // 只要该IP没有超出IP网段范围，就继续循环随机
			r.firstIP[15] = randIPEndWith(255) // 随机IP的最后一段
			r.firstIP[14] = randIPEndWith(255) // 随机IP的倒数第二段

			targetIP := make([]byte, len(r.firstIP))
			copy(targetIP, r.firstIP)
			r.appendIP(targetIP) // 加入IP地址池

			for i := 13; i >= 0; i-- { // 从倒数第三位开始往前随机
				tempIP := r.firstIP[i]
				r.firstIP[i] += randIPEndWith(255)
				if r.firstIP[i] >= tempIP {
					break
				}
			}
		}
	}
}

// loadIPRanges 从文件或字符串中加载IP范围
func loadIPRanges() []*net.IPAddr {
	ranges := newIPRanges()
	if IPText != "" { // 从参数中获取IP段数据
		IPs := strings.Split(IPText, ",")
		for _, IP := range IPs {
			IP = strings.TrimSpace(IP)
			if IP == "" {
				continue
			}
			ranges.parseCIDR(IP)
			if isIPv4(IP) {
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	} else { // 从文件中获取IP段数据
		if IPFile == "" {
			IPFile = defaultInputFile
		}
		file, err := os.Open(IPFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ranges.parseCIDR(line)
			if isIPv4(line) {
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	}
	return ranges.ips
}

func main() {
	ips := loadIPRanges() // 获取IP列表

	// 创建文件
	file, err := os.Create("ip_CFip.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// 将IP地址写入文件
	for _, ip := range ips {
		ipStr := ip.String() // 将 *net.IPAddr 转换为字符串
		_, err := file.WriteString(ipStr + "\n")
		if err != nil {
			log.Fatal(err)
		}
	}
}
