.PHONY: all pipe-tf pipe-tf2 pipe-model-tf2 clean pktgen

all: proto

pipe-tf:
	@echo "\033[32m----- Compiling pipelines for Tofino -----\033[0m"
	echo "Not implement yet"

pipe-tf2:
	@echo "\033[32m----- Compiling pipelines for Tofino 2 -----\033[0m"
	echo "Not implement yet"

pipe-model-tf2:
	@echo "\033[32m----- Compiling pipelines for Tofino Model with Tofino2 -----\033[0m"
	echo "Not implement yet"

clean:
	@echo "\033[32m----- Clear all environment -----\033[0m"
	echo "Not implement yet"

pktgen:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pktgen pktgen.go