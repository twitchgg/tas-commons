RPC_DIR := ./pkg/proto
OUT_DIR := ./pkg/pb

.PHONY: clean-proto clean-all

all: clean-all compile-all

init:
	go mod tidy
	mkdir -p $(BUILD_DIR)

compile-all: compile-proto

compile-proto: clean-proto
	for f in $$(ls $(RPC_DIR)/*.proto) ; do \
	 	protoc --proto_path=. --go_out=$(OUT_DIR) \
			--go-grpc_out=require_unimplemented_servers=false:$(OUT_DIR) $$f ;  \
	done

clean-proto:
	rm -f $(OUT_DIR)/*.pb.go

clean-all: clean-proto
