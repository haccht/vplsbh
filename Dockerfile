FROM golang:1.13

RUN apt-get -y update && \
    apt-get -y install libpcap-dev

ENV CGO_ENABLE=0 GOOS=linux GOARCH=amd64 GOBIN=/app/build

WORKDIR /app
VOLUME  /app/build

COPY go.mod go.sum ./
RUN  go mod download
