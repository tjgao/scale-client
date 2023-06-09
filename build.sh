#!/bin/sh
# go get github.com/gorilla/websocket
# go get github.com/sirupsen/logrus

mkdir -p build
build_time=$(date '+%F_%H:%M:%S')
build_hash=$(git rev-parse HEAD)
GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Commit=${build_time}__$build_hash" -o build/sc.linux

GOOS=windows GOARCH=amd64 go build -ldflags="-X main.Commit=${build_time}__$build_hash" -o build/sc.exe

GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.Commit=${build_time}__$build_hash" -o build/sc.mac

