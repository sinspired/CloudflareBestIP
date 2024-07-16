package main

import (
	"archive/zip"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var (
	ipFile_NoTLS = "ip_Fofa-0.txt"
	ipFile_TLS   = "ip_Fofa.txt"
	zipFile      = "Fofas.zip"
)

func main() {
	// 接受文件夹参数
	folder := "FofaCSV"
	outputFolder := folder + "Output"
	os.Mkdir(outputFolder, 0o755)

	fmt.Println("开始处理文件夹:", folder)

	// 遍历文件夹中的所有CSV文件
	files, err := ioutil.ReadDir(folder)
	if err != nil {
		fmt.Println("读取文件夹错误:", err)
		return
	}

	var zipFiles []string

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".csv" {
			fmt.Println("处理文件:", file.Name())
			processCSV(filepath.Join(folder, file.Name()), outputFolder, &zipFiles)
		}
	}
	// fmt.Printf("\nNoTLS IP文件已生成：%s\n", filepath.Join(outputFolder, ipFile_NoTLS))
	fmt.Printf("\ntlsIP文件已生成：%s\n", filepath.Join(outputFolder, ipFile_TLS))

	// 压缩生成的txt文件
	zipFilePath := filepath.Join(outputFolder, zipFile)
	err = createZip(zipFilePath, zipFiles)
	if err != nil {
		fmt.Println("压缩文件错误:", err)
		return
	}

	fmt.Println("压缩文件已生成:", zipFilePath)

	// 复制文件到程序所在文件夹
	copyFile(zipFilePath, zipFile)
	// copyFile(filepath.Join(outputFolder, ipFile_NoTLS), ipFile_NoTLS)
	copyFile(filepath.Join(outputFolder, ipFile_TLS), ipFile_TLS)

	fmt.Println("文件复制完成")
}

func processCSV(filePath, outputFolder string, zipFiles *[]string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("打开文件错误:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	headers, err := reader.Read()
	if err != nil {
		fmt.Println("读取CSV标题错误:", err)
		return
	}

	// 获取各列的索引
	var ipIndex, portIndex, countryIndex, protocolIndex, orgIndex int
	for i, header := range headers {
		switch header {
		case "ip":
			ipIndex = i
		case "port":
			portIndex = i
		case "country":
			countryIndex = i
		case "protocol":
			protocolIndex = i
		case "as_organization":
			orgIndex = i
		}
	}

	var ips, ports, countries, protocols, orgs []string
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("读取CSV记录错误:", err)
			return
		}
		ips = append(ips, record[ipIndex])
		ports = append(ports, record[portIndex])
		countries = append(countries, record[countryIndex])
		protocols = append(protocols, record[protocolIndex])
		orgs = append(orgs, record[orgIndex])
	}
	cleanIPs := []string{}
	for i, ip := range ips {
		
		if !strings.Contains(orgs[i], "Alibaba") && !strings.Contains(orgs[i], "Cloudflare") {
			cleanIPs = append(cleanIPs, ip)
		}
	}
	uniqueIPs := unique(cleanIPs)

	if allEqual(ports) {
		protocol := "0"
		if protocols[0] == "https" {
			protocol = "1"
		}
		if allEqual(countries) {
			fileName := fmt.Sprintf("%s-%s-%s.txt", countries[0], protocol, ports[0])
			writeToFile(filepath.Join(outputFolder, fileName), uniqueIPs)
			*zipFiles = append(*zipFiles, filepath.Join(outputFolder, fileName))
		} else {
			fileName := fmt.Sprintf("Fofa-%s-%s.txt", protocol, ports[0])
			writeToFile(filepath.Join(outputFolder, fileName), uniqueIPs)
			*zipFiles = append(*zipFiles, filepath.Join(outputFolder, fileName))
		}
	} else {
		httpIPs, httpsIPs := []string{}, []string{}
		for i, ip := range ips {
			if !strings.Contains(orgs[i], "Alibaba") && !strings.Contains(orgs[i], "Cloudflare") {
				if protocols[i] == "http" {
					httpIPs = append(httpIPs, fmt.Sprintf("%s:%s", ip, ports[i]))
				} else {
					httpsIPs = append(httpsIPs, fmt.Sprintf("%s:%s", ip, ports[i]))
				}
			}
		}
		writeToFile(filepath.Join(outputFolder, ipFile_NoTLS), unique(httpIPs))
		writeToFile(filepath.Join(outputFolder, ipFile_TLS), unique(httpsIPs))
	}
}

func allEqual(slice []string) bool {
	for _, v := range slice {
		if v != slice[0] {
			return false
		}
	}
	return true
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func writeToFile(filePath string, data []string) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Println("写入文件错误:", err)
		return
	}
	defer file.Close()

	for _, line := range data {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			fmt.Println("写入文件错误:", err)
			return
		}
	}
}

func createZip(zipFileName string, files []string) error {
	newZipFile, err := os.Create(zipFileName)
	if err != nil {
		return err
	}
	defer newZipFile.Close()

	zipWriter := zip.NewWriter(newZipFile)
	defer zipWriter.Close()

	for _, file := range files {
		if err := addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}
	return nil
}

func addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	header.Name = filepath.Base(filename)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, fileToZip)
	return err
}

func copyFile(src, dst string) {
	sourceFile, err := os.Open(src)
	if err != nil {
		fmt.Println("复制文件错误:", err)
		return
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		fmt.Println("复制文件错误:", err)
		return
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		fmt.Println("复制文件错误:", err)
	}
}
