package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jessevdk/go-flags"
	"google.golang.org/grpc"

	pb "github.com/haccht/vplsbh/proto"
)

const (
	snapshotLen = 65536
)

type cmdOption struct {
	Address      string `short:"a" long:"addr"      description:"gRPC address to connect to" value-name:"<addr>" default:"127.0.0.1:50005"`
	BPFFilter    string `short:"e" long:"bpf"       description:"filter packets by BPF primitive" value-name:"<expression>"`
	DomainFilter string `short:"d" long:"domain"    description:"filter packets by Bridge-Domain name" value-name:"<bdname>"`
	PacketCount  uint   `short:"c" long:"count"     description:"exit after reading specified number of packets" value-name:"<count>"`
	Duration     uint   `short:"t" long:"duration"  description:"exit after specified seconds have elapsed" value-name:"<seconds>"`
	WriteFile    string `short:"w" long:"write"     description:"write packets to the pcap file" value-name:"<filepath>"`
}

func NewCmdOption(args []string) (*cmdOption, error) {
	var opt cmdOption

	_, err := flags.ParseArgs(&opt, args)
	if err != nil {
		return nil, err
	}
	return &opt, nil
}

func main() {
	opt, err := NewCmdOption(os.Args)
	if err != flag.ErrHelp {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var w *pcapgo.Writer
	if opt.WriteFile != "" {
		f, err := os.Create(opt.WriteFile)
		if err != nil {
			log.Fatalf("failed to open file: %v", err)
		}
		defer f.Close()

		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	}

	conn, err := grpc.Dial(opt.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect with server: %v", err)
	}
	defer conn.Close()

	req := &pb.Request{Filter: opt.BPFFilter, Domain: opt.DomainFilter}
	ctx, cancel := context.WithCancel(context.Background())
	if opt.Duration != 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opt.Duration))
	}
	defer cancel()

	client := pb.NewBumSniffServiceClient(conn)
	stream, err := client.Sniff(ctx, req)
	if err != nil {
		log.Fatalf("failed to open stream: %v", err)
	}

	var np uint
	for {
		recv, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				break
			}
			log.Fatalf("stop receiving packets: %v", err)
		}

		packet := gopacket.NewPacket(recv.Data, layers.LayerTypeEthernet, gopacket.Lazy)

		md := packet.Metadata()
		ci := gopacket.CaptureInfo{Timestamp: recv.Timestamp.AsTime(), CaptureLength: len(recv.Data), Length: len(recv.Data)}
		md.CaptureInfo = ci

		fmt.Println(packet)
		if w != nil {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

		np++
		if opt.PacketCount != 0 && opt.PacketCount <= np {
			break
		}
	}
}
