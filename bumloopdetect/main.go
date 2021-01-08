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
	Database = "vplsbh"
	Series   = "bumloop"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

type cmdOption struct {
	GRPCAddress string `short:"a" long:"addr"      description:"gRPC address to connect to" value-name:"<addr>"`
	InfluxDB    string `short:"d" long:"influxdb"  description:"Write packets to InfluxDB" value-name:"<url>" default:"http://localhost:8086"`
	Interval    uint   `short:"t" long:"interval"  description:"Interval time in sec to record" value-name:"<interval>" default:"3"`
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

type packetEntry struct {
	Domain, Remote, SrcMAC string
}

func record(db influx.Client, ch chan *packetEntry, interval uint) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	count := make(map[packetEntry]int)
	bpcfg := influx.BatchPointsConfig{Database: Database, Precision: "s"}

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

				pt, _ := influx.NewPoint(Series, tags, fields)
				bp.AddPoint(pt)

				n += c
				delete(count, e)
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

	db, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: opt.InfluxDB})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	conn, err := grpc.Dial(opt.GRPCAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect with server %v", err)
	}
	defer conn.Close()

	ch := make(chan *packetEntry, 1000)
	defer close(ch)

	go record(db, ch, opt.Interval)

	client := pb.NewBumSniffServiceClient(conn)
	stream, err := client.Sniff(context.Background(), &pb.Filter{})
	if err != nil {
		log.Fatalf("open stream error %v", err)
	}

	fdb := cache.NewTTLCache(12 * time.Hour) // In-memory KVS to map Domain, SrcMAC -> Domain, SrcMAC, Remote
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

		key := packetEntry{SrcMAC: eth.SrcMAC.String(), Domain: recv.Domain}
		val := packetEntry{SrcMAC: eth.SrcMAC.String(), Domain: recv.Domain, Remote: recv.Remote}

		v, ok := fdb.Get(key)
		fdb.Set(key, &val)
		if !ok {
			continue
		}

		// Get the last learned Domain, Remote and SrcMAC and check if the Remote has changed
		learned := v.(*packetEntry)
		if recv.Domain == learned.Domain && recv.Remote != learned.Remote {
			ch <- &val
		}
	}
}