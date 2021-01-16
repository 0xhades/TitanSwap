# TitanSwap
an instagram swapper, written in go, uses the regular http.client library

# installation
```
git clone https://github.com/0xhades/TitanSwap.git ~/go/src/TitanSwap
```
# libraries
```
go get github.com/fatih/color
go get github.com/Pallinder/go-randomdata
```
# run
```
go run TitanSwap
```
# build
```
#local OS
go build -ldflags "-s -w" -o TitanSwap titanswap

#Windows
GOOS=windows arch=amd64 go build -ldflags "-s -w" -o TitanSwap titanswap

#linux
GOOS=linux arch=386 go build -ldflags "-s -w" -o TitanSwap titanswap
```
# about
instagram: @0xhades @ctpe
