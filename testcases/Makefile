
.PHONY: all

all:
	@cd ./openssl101 && cp ~/workspace/protocol/benchmark/openssl101/libssl.a . && cp ~/workspace/protocol/benchmark/openssl101/libcrypto.a . && ./build
	@cd ./openssl110 && cp ~/workspace/protocol/benchmark/openssl110/libssl.a . && cp ~/workspace/protocol/benchmark/openssl110/libcrypto.a . && ./build

clean:
	rm -rf openssl101/out/*/*
	rm -f openssl101/openssl101
	rm -rf openssl110/out/*/*
	rm -f openssl110/openssl110


