package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jessevdk/go-flags"
	"google.golang.org/grpc"

	pb "github.com/haccht/vplsbh/pkg/grpc"
)

const (
	snapshotLen = 65536
)

type cmdOption struct {
	Address      string `short:"a" long:"addr"      description:"gRPC address to connect to" value-name:"<addr>" default:"127.0.0.1:50005"`
	BPFFilter    string `short:"e" long:"bpf"       description:"filter packets by BPF primitive" value-name:"<expression>"`
	RemoteFilter string `short:"r" long:"remote"    description:"filter packets by Remote-Router name" value-name:"<remote>"`
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
	if err != nil {
		if fe, ok := err.(*flags.Error); ok && fe.Type == flags.ErrHelp {
			os.Exit(0)
		}
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
		w.WriteFileHeader(snapshotLen, layers.LinkTypeIPv4)
	}

	conn, err := grpc.Dial(opt.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect with server: %v", err)
	}
	defer conn.Close()

	req := &pb.Request{Filter: opt.BPFFilter, Remote: opt.RemoteFilter, Domain: opt.DomainFilter}
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

		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolEtherIP,
			SrcIP:    net.ParseIP(recv.Peerid),
			DstIP:    net.ParseIP("0.0.0.0"),
		}
		etherip := &layers.EtherIP{
			Version: 3,
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		var bytes []byte

		if bytes, err = buf.PrependBytes(len(recv.Data)); err != nil {
			break
		}
		copy(bytes, recv.Data)

		if bytes, err = buf.PrependBytes(2); err != nil {
			break
		}
		bytes[0] = (etherip.Version << 4)

		if err := ip.SerializeTo(buf, opts); err != nil {
			break
		}

		packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Lazy)
		md := packet.Metadata()
		ci := gopacket.CaptureInfo{Timestamp: recv.Timestamp.AsTime(), CaptureLength: len(packet.Data()), Length: len(packet.Data())}
		md.CaptureInfo = ci

		fmt.Printf("DOMAIN: %s, REMOTE: %s, LABEL: %d\n", recv.Domain, recv.Remote, recv.Label)
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
