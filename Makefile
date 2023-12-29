TARGET=enetmon
VERSION=0.0.1

.PHONY: all
all: bpf_bpfel.go
	go build -o ${TARGET} -trimpath -ldflags "-s -w -X main.version=${VERSION}" enetmon.go bpf_bpfel.go

bpf_bpfel.go: enetmon.bpf.c
	go generate enetmon.go

.PHONY: run
run: all
	sudo ./${TARGET}

.PHONY: clean
clean:
	rm -f ${TARGET}

.PHONY: format
format:
	clang-format -i enetmon.bpf.c
	go fmt ./...

.PHONY: lint
lint:
	golangci-lint run ./...