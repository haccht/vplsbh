.PHONY: build

build:
	docker run --rm -v ${CURDIR}:/app -v ${CURDIR}/build:/app/build vplsbh go install ./...

docker: Dockerfile
	docker build -t vplsbh .

grpc: api/bumstream.proto
	cd api && \
	protoc --go_out=../pkg/grpc --go_opt=paths=source_relative --go-grpc_out=../pkg/grpc --go-grpc_opt=paths=source_relative --go-grpc_opt require_unimplemented_servers=false bumstream.proto
