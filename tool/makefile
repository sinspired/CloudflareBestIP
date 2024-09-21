# Makefile

.PHONY: all mergeCSV QueryDownload tcpTest

all: mergeCSV QueryDownload tcpTest

mergeCSV:
	go run mergeCSV.go $(f)

QueryDownload:
	go run QueryDownload.go

tcpTest:
	go run tcpTest.go $(ip)

buildreparse:
	go build -o ../reParseResultTxtFile.exe reParseResultTxtFile.go
	copy "..\reParseResultTxtFile.exe" "F:\worknow\iplab\"
	copy "..\reParseResultTxtFile.exe" "F:\"

buildfofa:
	go build -o ../processFofaCSV.exe processFofaCSV.go
	copy "..\processFofaCSV.exe" "F:\"