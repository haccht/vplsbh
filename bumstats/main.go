package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jessevdk/go-flags"
	"google.golang.org/grpc"

	_ "github.com/influxdata/influxdb1-client"
	influx "github.com/influxdata/influxdb1-client/v2"

	pb "github.com/haccht/vplsbh/proto"
)

const (
	influxDBAddr   = "http://localhost:8086"
	influxDBName   = "vplsbh"
	influxDBSeries = "bumstats"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return fallback
}

type cmdOption struct {
	Address  string `short:"a" long:"addr"      description:"gRPC address to connect to" value-name:"<addr>"`
	Interval uint   `short:"t" long:"interval"  description:"Interval time in sec to record" value-name:"<interval>" default:"3"`
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
	return &opt, nil
}

type packetTags struct {
	Domain, Remote, Protocol, Type, Length string
}

func record(db influx.Client, ch chan *packetTags, interval uint) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	bpcfg := influx.BatchPointsConfig{Database: getEnv("INFLUXDB_NAME", influxDBName), Precision: "s"}
	count := make(map[packetTags]uint)

	for {
		select {
		case s, ok := <-ch:
			if !ok {
				tick.Stop()
				return
			}

			count[*s] += 1
		case <-tick.C:
			bp, _ := influx.NewBatchPoints(bpcfg)

			var n uint
			for s, c := range count {
				tags := map[string]string{"domain": s.Domain, "remote": s.Remote, "protocol": s.Protocol, "type": s.Type, "length": s.Length}
				fields := map[string]interface{}{"event": c}

				pt, _ := influx.NewPoint(getEnv("INFLUXDB_SERIES", influxDBSeries), tags, fields)
				bp.AddPoint(pt)

				n += c
				delete(count, s)
			}

			if err := db.Write(bp); err != nil {
				logger.Printf("Could not write points to InfluxDB: %s", err.Error())
			} else {
				logger.Printf("Dump %d points to InfluxDB.", n)
			}
		}
	}
}

func main() {
	opt, err := NewCmdOption(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	db, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: getEnv("INFLUXDB_ADDR", influxDBAddr)})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	conn, err := grpc.Dial(opt.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect with server %v", err)
	}
	defer conn.Close()

	ch := make(chan *packetTags, 1000)
	defer close(ch)

	go record(db, ch, opt.Interval)

	client := pb.NewBumSniffServiceClient(conn)
	stream, err := client.Sniff(context.Background(), &pb.Filter{})
	if err != nil {
		log.Fatalf("open stream error %v", err)
	}

	for {
		recv, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("cannot receive %v", err)
		}

		packet := gopacket.NewPacket(recv.Data, layers.LayerTypeEthernet, gopacket.Lazy)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)

		var typeString, lengthString string

		// Broadcast, Multicast, Unknown-Unicast
		switch {
		case reflect.DeepEqual(eth.DstMAC, layers.EthernetBroadcast):
			typeString = "broadcast"
		case eth.DstMAC[0]&0x01 == 1: //I/G bit
			typeString = "multicast"
		default:
			typeString = "unicast"
		}

		// Frame size (include FCS)
		length := len(eth.Contents) + len(eth.Payload) + 4
		switch {
		case length < 128:
			lengthString = "64-127"
		case length < 256:
			lengthString = "128-255"
		case length < 512:
			lengthString = "256-511"
		case length < 1024:
			lengthString = "512-1023"
		case length < 1519:
			lengthString = "1024-1518"
		default:
			lengthString = "1519-"
		}

		ch <- &packetTags{
			Domain:   recv.Domain,
			Remote:   recv.Remote,
			Type:     typeString,
			Length:   lengthString,
			Protocol: eth.EthernetType.String(),
		}
	}
}
