package main

import (
    "encoding/csv"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "path"
    "path/filepath"
    //"strings"
    "sync"

    "github.com/PuerkitoBio/goquery"
)

// fetchLinks 从指定的URL获取所有以.csv结尾的下载链接
func fetchLinks(baseURL string) ([]string, error) {
    res, err := http.Get(baseURL)
    if err != nil {
        return nil, err
    }
    defer res.Body.Close()

    if res.StatusCode != 200 {
        return nil, fmt.Errorf("status code error: %d %s", res.StatusCode, res.Status)
    }

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        return nil, err
    }

    var links []string
    doc.Find(".fname1").Each(func(index int, item *goquery.Selection) {
        link, _ := item.Attr("href")
        //if strings.HasSuffix(link, ".csv") {
            // 处理相对路径
            absoluteURL := resolveURL(baseURL, link)
            links = append(links, absoluteURL)
        //}
    })

    return links, nil
}

// resolveURL 将相对路径转换为绝对路径
func resolveURL(baseURL, relativeURL string) string {
    base, err := url.Parse(baseURL)
    if err != nil {
        return ""
    }
    ref, err := url.Parse(relativeURL)
    if err != nil {
        return ""
    }
    return base.ResolveReference(ref).String()
}

// downloadFileWg 下载指定URL的文件并保存到本地
func downloadFileWg(baseURL, fileURL, baseDir string, wg *sync.WaitGroup) {
    defer wg.Done()

    // 获取文件名和目录
    u, err := url.Parse(fileURL)
    if err != nil {
        fmt.Println("Error parsing URL:", err)
        return
    }
    filePath := u.Path
    fileName := path.Base(filePath)
    dir := path.Join(baseDir, path.Dir(filePath))

    // 创建目录
    if err := os.MkdirAll(dir, os.ModePerm); err != nil {
        fmt.Println("Error creating directory:", err)
        return
    }

    // 创建文件
    out, err := os.Create(filepath.Join(dir, fileName))
    if err != nil {
        fmt.Println("Error creating file:", err)
        return
    }
    defer out.Close()

    // 发送HTTP请求下载文件
    resp, err := http.Get(fileURL)
    if err != nil {
        fmt.Println("Error downloading file:", err)
        return
    }
    defer resp.Body.Close()

    // 将响应内容写入文件
    _, err = io.Copy(out, resp.Body)
    if err != nil {
        fmt.Println("Error writing to file:", err)
        return
    }

    fmt.Println("Downloaded:", filepath.Join(dir, fileName))
}

func main() {
    baseURL := "https://cloud.bhqt.fun/?dir=/碧海反代IP测试工具"

    // 获取程序当前工作目录
    baseDir, err := os.Getwd()
    if err != nil {
        fmt.Println("Error getting current directory:", err)
        return
    }
 baseDir= baseDir+"/Test"
    // 获取所有下载链接
    links, err := fetchLinks(baseURL)
    if err != nil {
        fmt.Println("Error fetching links:", err)
        return
    }

    // 创建CSV文件保存链接
    file, err := os.Create("download_links.csv")
    if err != nil {
        fmt.Println("Cannot create file:", err)
        return
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()
    writer.Write([]string{"Link"})

    var wg sync.WaitGroup
    for _, link := range links {
        writer.Write([]string{link}) // 将链接写入CSV文件
        wg.Add(1)
        go downloadFileWg(baseURL, link, baseDir, &wg) // 并发下载文件
    }

    wg.Wait() // 等待所有下载完成
    fmt.Println("All files downloaded and links saved to download_links.csv")
}
