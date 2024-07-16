# CloudflareBestIP

[![Go Version](https://img.shields.io/github/go-mod/go-version/sinspired/CloudflareBestIP?logo=go&label=Go)](https://github.com/sinspired/CloudflareBestIP)
[![Release Version](https://img.shields.io/github/v/release/sinspired/CloudflareBestIP?display_name=tag&logo=github&label=Release)](https://github.com/sinspired/CloudflareBestIP/releases/latest)
[![GitHub repo size](https://img.shields.io/github/repo-size/sinspired/CloudflareBestIP?logo=github)
](https://github.com/sinspired/CloudflareBestIP)
[![GitHub last commit](https://img.shields.io/github/last-commit/sinspired/CloudflareBestIP?logo=github&label=最后提交：)](ttps://github.com/sinspired/CloudflareBestIP)

CloudflareBestIP 采用go编写的小工具。能够自动下载知名的几个ip库，自适应识别文件格式进行测速优选。如设置了domain和token，优选ip结果可直接上传到云端，实现自动化更新。

# 安装

首先安装 Golang 和 Git，然后在终端中运行以下命令：

```bash
git clone https://github.com/sinspired/CloudflareBestIP.git
cd CloudflareBestIP
go build -o BestipTest.exe main.go update.go
```

这将编译可执行文件 BestipTest.exe。

# 参数说明

**CloudflareBestIP** 可以接受以下参数：

* -file IP地址文件名称(*.txt或*.zip) (default "txt.zip")
* -countries 国家代码(US,SG,JP,DE...)，以逗号分隔，留空时检测所有
* -domain 上传地址，默认为空,用Text2KV项目建立的简易文件存储storage.example.com
* -token 上传地址的token，默认为空
* -httplimit HTTP最大延迟(ms) (default 1000)
* -iplab 为true时检查ip库中的文件并依次下载 (default false)
* -max 并发请求最大协程数 (default 1000)
* -mulnum float
        多协程测速造成测速不准，可进行倍数补偿 (default 1)
* -outfile 输出文件名称(自动设置) (default "result.csv")
* -port 默认端口 (default 443)
* -speedlimit 最低下载速度(MB/s) (default 4)
* -speedtest 下载测速协程数量,设为0禁用测速 (default 5)
* -tcplimit TCP最大延迟(ms) (default 1000)
* -tls  是否启用TLS (default true)

* -url 测速文件地址 (default "speed.cloudflare.com/__down?bytes=500000000")
* -num 测速结果数量 (default 6)
* -dlall 为true时检查ip库中的文件并依次下载

命令行键入 `-h` `help` 获取帮助 `./CloudflareBestIP.exe -h`

# 运行

在终端中运行以下命令来启动程序：

### 不带参数运行

```powershell
./BestipTest.exe
```

默认参数会检测网络情况（请关闭代理），之后会自动下载一个ip库并自动测速

### 设置参数

```powershell
./BestipTest.exe -tcplimit=300 -httplimit=300 -speedlimit=5 -tls=true -port=443 -iplab=false -max=1000 -speedtest=5 -file="txt.zip" -outfile="result.csv" -domain="x.xxx.com" -token="password" -countries="US,Sg,DE" -num=10 -dlall=false
```

请替换参数值以符合您的实际需求。

**注意：**

`-domain="x.xxx.com"` 和 `-token="password"`,当优选结果>0时会提示是否上传优选ip结果到云端，需要输入域名和token。可以参考<https://github.com/sinspired/CF-Workers-TEXT2KV> 自行搭建文件存储服务

**文件格式：**

支持txt格式和zip格式，部分zip文件程序可以自动解压、合并、去重。支持的ip格式如下：

* 单行ip的txt文件，程序按照指定的端口进行检测
* `ip:port` 格式的txt文件，程序会识别ip和端口号
* CIDR 格式的ip文件
* 如果是从FOFA等网站下载的文件，可以把文件名设置为`ASN-Tls-PORT.txt`，把多个文件打包成一个`zip`文件,程序可以直接识别解压，然后根据文件名的tls状态和端口号检测。Tls 的值为0或1，对应false/true。

**命名规范：**

`-file` 参数应遵循以下命名规范

* txt文件，可命名为 ip_filename.txt，程序会识别"_"切出filename，以便设置输出文件名 result_filename.csv
* zip文件，直接filename.zip

**输出结果：**

优化了命令行界面输出，可以直观查看程序执行情况，最终会把优选ip结果存入  `result_"源文件名".csv` 中。


# 最新发行版下载

[![Release Detail](https://img.shields.io/github/v/release/sinspired/CloudflareBestIP?sort=date&display_name=release&logo=github&label=Release)](https://github.com/sinspired/CloudflareBestIP/releases/latest)
