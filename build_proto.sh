#!/bin/sh
go install -v google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
go run ./infra/vprotogen/