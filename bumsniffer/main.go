package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jessevdk/go-flags"
	"github.com/rs/xid"
	"golang.org/x/sync/errgroup"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/haccht/vplsbh/cache"
	"github.com/haccht/vplsbh/l2vpn"
	pb "github.com/haccht/vplsbh/proto"
)

const (
	SnapshotLen = 65536
	Promiscuous = true
	RedisURL    = "redis://localhost:6379"
)

type cmdOption struct {
	GRPCAddress string `short:"a" long:"addr"      description:"gRPC address to serve" value-name:"<addr>"`
	Interface   string `short:"i" long:"interface" description:"Read packets from the interface" value-name:"<interface>"`
	Filepath    string `short:"r" long:"read"      description:"Read packets from the pcap file" hidden:"true"`
}

func NewCmdOption(args []string) (*cmdOption, error) {
	var opt cmdOption

	_, err := flags.ParseArgs(&opt, args)
	if err != nil {
		if err != flag.ErrHelp {
			os.Exit(0)
		}
		return nil, err
	}

	if opt.Interface == "" && opt.Filepath == "" {
		return nil, fmt.Errorf("the required flag '-i' was not specified")
	}

	return &opt, nil
}

type sniffer struct {
	sync.RWMutex

	cache    *cache.TTLCache
	channels []chan<- *pb.Packet
}

func NewSniffer() *sniffer {
	// Redis pool to lookup when the label key would not be found or expited.
	r := &redis.Pool{
		MaxIdle:     2,
		MaxActive:   4,
		IdleTimeout: 5 * time.Minute,
		Dial:        func() (redis.Conn, error) { return redis.DialURL(RedisURL) },
	}

	// Set a lookup function used when the label key would not be found or be expired.
	c := cache.NewTTLCache(5 * time.Minute)
	c.SetLookupFunc(func(k interface{}) (interface{}, bool) {
		conn := r.Get()
		defer conn.Close()

		key := fmt.Sprintf("label:%d", k)
		val, err := redis.Values(conn.Do("HMGET", key, "Domain", "Remote"))
		if err != nil {
			return nil, false
		}

		t := &struct{ Domain, Remote string }{}
		if _, err := redis.Scan(val, &t.Domain, &t.Remote); err != nil {
			return nil, false
		}

		c.SetWithExpiration(k, t, cache.DefaultExpiration)
		return t, true
	})

	return &sniffer{
		cache:    c,
		channels: []chan<- *pb.Packet{},
	}

}

func (s *sniffer) Serve(handle *pcap.Handle) error {
	var eth layers.Ethernet
	var vpls l2vpn.VPLS
	var pwmcw l2vpn.PWMCW
	var parser *gopacket.DecodingLayerParser

	decoded := make([]gopacket.LayerType, 0, 3)

	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			return err
		}

		// Decode the outer Ethernet layer
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth)
		parser.DecodeLayers(data, &decoded)

		// Decode the VPLS and inner Ethernet layers
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeMPLS, &vpls, &pwmcw, &eth)
		parser.DecodeLayers(eth.Payload, &decoded)

		if len(decoded) < 3 ||
			decoded[0] != layers.LayerTypeMPLS ||
			decoded[1] != l2vpn.LayerTypePWMCW ||
			decoded[2] != layers.LayerTypeEthernet {
			continue
		}

		v, ok := s.cache.Get(vpls.Label)
		if !ok {
			continue
		}

		rawData := append(eth.Contents, eth.Payload...)
		dupData := make([]byte, len(rawData))
		copy(dupData, rawData)

		t := v.(*struct{ Domain, Remote string })
		p := &pb.Packet{
			Data:      dupData,
			Label:     vpls.Label,
			Domain:    t.Domain,
			Remote:    t.Remote,
			Timestamp: timestamppb.New(ci.Timestamp),
		}

		s.Publish(p)
	}
}

func (s *sniffer) Publish(p *pb.Packet) {
	s.RLock()
	defer s.RUnlock()

	for _, ch := range s.channels {
		ch <- p
	}
}

func (s *sniffer) Subscribe(ch chan<- *pb.Packet) {
	s.Lock()
	defer s.Unlock()

	s.channels = append(s.channels, ch)
}

func (s *sniffer) Unsubscribe(ch chan<- *pb.Packet) {
	s.Lock()
	defer s.Unlock()

	for i, v := range s.channels {
		if v == ch {
			s.channels = append(s.channels[:i], s.channels[i+1:]...)
		}
	}
}

func (s *sniffer) Sniff(filter *pb.Filter, stream pb.BumSniffService_SniffServer) (err error) {
	var bpf *pcap.BPF
	if filter.Bpf != "" {
		bpf, err = pcap.NewBPF(layers.LinkTypeEthernet, SnapshotLen, filter.Bpf)
		if err != nil {
			return err
		}
	}

	id := xid.New()
	ch := make(chan *pb.Packet, 1000)
	defer close(ch)

	s.Subscribe(ch)
	defer s.Unsubscribe(ch)

	log.Printf("registered sniffer[%s]: domain='%s' filter='%s'", id.String(), filter.Domain, filter.Bpf)
	for packet := range ch {
		if filter.Domain != "" && filter.Domain != packet.Domain {
			continue
		}

		if filter.Bpf != "" {
			ci := gopacket.CaptureInfo{
				Timestamp:     packet.Timestamp.AsTime(),
				CaptureLength: len(packet.Data),
				Length:        len(packet.Data),
			}
			if !bpf.Matches(ci, packet.Data) {
				continue
			}
		}

		//fmt.Println(gopacket.NewPacket(packet.Data, layers.LayerTypeEthernet, gopacket.Lazy))
		if err := stream.Send(packet); err != nil {
			log.Printf("failed to write to the stream: %v", err)
			break
		}
	}

	log.Printf("unregistered sniffer[%s]", id.String())
	return nil
}

func main() {
	// MPLS Decoder should assume that the MPLS payload is a Ethenet frame with a control-word header
	layers.MPLSPayloadDecoder = &l2vpn.PWMCWDecoder{ControlWord: true}

	sniffServer := NewSniffer()
	opt, err := NewCmdOption(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var errGroup errgroup.Group
	var openHandle func() (*pcap.Handle, error)
	if opt.Interface != "" {
		openHandle = func() (*pcap.Handle, error) {
			return pcap.OpenLive(opt.Interface, SnapshotLen, Promiscuous, pcap.BlockForever)
		}
	} else if opt.Filepath != "" {
		openHandle = func() (*pcap.Handle, error) {
			return pcap.OpenOffline(opt.Filepath)
		}
	}

	errGroup.Go(func() error {
		log.Println("start gRPC server")

		listener, err := net.Listen("tcp", opt.GRPCAddress)
		if err != nil {
			return fmt.Errorf("Failed to listen: %v", err)
		}

		kaep := keepalive.EnforcementPolicy{MinTime: 5 * time.Second}
		grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep))
		pb.RegisterBumSniffServiceServer(grpcServer, sniffServer)
		if err := grpcServer.Serve(listener); err != nil {
			return fmt.Errorf("failed to start gRPC server: %v", err)
		}

		return nil
	})

	errGroup.Go(func() error {
		log.Println("start BUM sniffer server")

		handle, err := openHandle()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer handle.Close()

		if err := sniffServer.Serve(handle); err != nil {
			return fmt.Errorf("failed to start BUM sniffer server: %v", err)
		}

		return nil
	})

	if err := errGroup.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
