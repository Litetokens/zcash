#!/bin/sh
protoc -I ./ --grpc_out=. --plugin=protoc-gen-grpc=/Users/tron/code/grpc_1.14.0/houlei/bin/grpc_cpp_plugin  geneproof.proto
protoc -I ./ --cpp_out=./ geneproof.proto
