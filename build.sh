#!/bin/sh
# go get github.com/gorilla/websocket
# go get github.com/sirupsen/logrus

mkdir -p build

GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Commit=$(git rev-parse HEAD)" -o build/sc.linux

GOOS=windows GOARCH=amd64 go build -ldflags="-X main.Commit=$(git rev-parse HEAD)" -o build/sc.exe

GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.Commit=$(git rev-parse HEAD)" -o build/sc.mac

