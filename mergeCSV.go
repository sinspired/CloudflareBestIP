package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	// 定义命令行参数
	flag.Parse()
	args := flag.Args()

	// 检查是否提供了文件夹路径
	if len(args) < 1 {
		fmt.Println("请提供文件夹路径（相对路径或绝对路径），例如：go run mergeCSV.go folderpath")
		return
	}

	// 文件夹路径
	folderPath := args[0]

	// 创建一个新的 TXT 文件来存储结果
	// https://codeload.github.com/ip-scanner/cloudflare/zip/refs/heads/main
	outputFile, err := os.Create("ip_Scanner.txt")
	if err != nil {
		fmt.Println("无法创建输出文件:", err)
		return
	}
	defer outputFile.Close()

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	// 遍历文件夹内所有 CSV 文件
	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".csv" {
			file, err := os.Open(path)
			if err != nil {
				fmt.Println("无法打开文件:", err)
				return err
			}
			defer file.Close()

			reader := csv.NewReader(file)
			for {
				record, err := reader.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					fmt.Println("读取文件错误:", err)
					return err
				}
				// 只写入第一列
				if len(record) > 0 {
					writer.WriteString(record[0] + "\n")
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println("遍历文件夹错误:", err)
		return
	}

	fmt.Println("合并完成，结果保存在 'ip_Scanner.txt'")
}
