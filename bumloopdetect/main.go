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
	"github.com/jessevdk/go-flags"
	"google.golang.org/grpc"

	_ "github.com/influxdata/influxdb1-client"
	influx "github.com/influxdata/influxdb1-client/v2"

	"github.com/haccht/vplsbh/cache"
	pb "github.com/haccht/vplsbh/proto"
)

const (
	influxDBAddr   = "http://localhost:8086"
	influxDBName   = "vplsbh"
	influxDBSeries = "bumloop"
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
	Address  string `short:"a" long:"addr"      description:"gRPC address to connect to" value-name:"<addr>" default:"127.0.0.1:50005"`
	Interval uint   `short:"t" long:"interval"  description:"Interval time in sec to record" value-name:"<interval>" default:"3"`
}

func NewCmdOption(args []string) (*cmdOption, error) {
	var opt cmdOption

	_, err := flags.ParseArgs(&opt, args)
	if err != nil {
		return nil, err
	}
	return &opt, nil
}

type packetFDBEntry struct {
	Domain, Remote, SrcMAC string
}

func record(db influx.Client, ch chan *packetFDBEntry, interval uint) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	count := make(map[packetFDBEntry]int)
	bpcfg := influx.BatchPointsConfig{Database: getEnv("INFLUXDB_NAME", influxDBName), Precision: "s"}

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				tick.Stop()
				return
			}

			count[*e] += 1
		case <-tick.C:
			bp, _ := influx.NewBatchPoints(bpcfg)

			var n int
			for e, c := range count {
				tags := map[string]string{"Domain": e.Domain, "Remote": e.Remote, "SrcMAC": e.SrcMAC}
				fields := map[string]interface{}{"count": c}

				pt, _ := influx.NewPoint(getEnv("INFLUXDB_SERIES", influxDBSeries), tags, fields)
				bp.AddPoint(pt)

				n += c
				delete(count, e)
			}

			if err := db.Write(bp); err != nil {
				logger.Printf("failed to write points: %v", err)
			} else {
				logger.Printf("dump %d points", n)
			}
		}
	}
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

	db, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: getEnv("INFLUXDB_ADDR", influxDBAddr)})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	conn, err := grpc.Dial(opt.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect with server: %v", err)
	}
	defer conn.Close()

	client := pb.NewBumSniffServiceClient(conn)
	stream, err := client.Sniff(context.Background(), &pb.Request{})
	if err != nil {
		log.Fatalf("failed to open stream:r %v", err)
	}

	ch := make(chan *packetFDBEntry, 1000)
	defer close(ch)

	go record(db, ch, opt.Interval)

	fdb := cache.NewTTLCache(12 * time.Hour)
	for {
		recv, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("failed to recieve packet: %v", err)
		}

		packet := gopacket.NewPacket(recv.Data, layers.LayerTypeEthernet, gopacket.Lazy)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)

		key := packetFDBEntry{SrcMAC: eth.SrcMAC.String(), Domain: recv.Domain}
		val := packetFDBEntry{SrcMAC: eth.SrcMAC.String(), Domain: recv.Domain, Remote: recv.Remote}

		v, ok := fdb.Get(key)
		fdb.Set(key, &val)
		if !ok {
			continue
		}

		// Get the last learned Domain, Remote and SrcMAC and check if the Remote has changed
		learned := v.(*packetFDBEntry)
		if recv.Domain == learned.Domain && recv.Remote != learned.Remote {
			ch <- &val
		}
	}
}
