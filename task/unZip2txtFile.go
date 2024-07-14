package task

import (
	"archive/zip"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type FileInfo struct {
	Name    string
	TLS     bool
	Port    int
	Content []byte
}

func UnZip2txtFile(zipPath string, outputPath string) ([]FileInfo, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var fileInfos []FileInfo
	pattern := regexp.MustCompile(`^(\w+)-(\d)-(\d+)\.txt$`)
	for _, f := range r.File {
		matches := pattern.FindStringSubmatch(f.Name)
		if len(matches) == 4 {
			tls, _ := strconv.Atoi(matches[2])
			port, _ := strconv.Atoi(matches[3])

			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			content, err := ioutil.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, err
			}

			fileInfos = append(fileInfos, FileInfo{
				Name:    f.Name,
				TLS:     tls == 1,
				Port:    port,
				Content: content,
			})
		}
	}

	if len(fileInfos) == 0 {
		// 如果不是 ASN 格式，则按照原来的逻辑处理
		return nil, mergeTextFiles(r, outputPath)
	}

	return fileInfos, nil
}

// 保留 mergeTextFiles 函数的实现...

func mergeTextFiles(r *zip.ReadCloser, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".txt") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outputFile, rc)
		if err != nil {
			rc.Close()
			return err
		}
		rc.Close()

		_, err = outputFile.WriteString("\n")
		if err != nil {
			return err
		}
	}

	return nil
}
