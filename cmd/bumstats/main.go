package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/haccht/vplsbh"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket/layers"
	"github.com/jessevdk/go-flags"

	_ "github.com/influxdata/influxdb1-client"
	influx "github.com/influxdata/influxdb1-client/v2"
)

const (
	Database = "vplsbh"
	Series   = "bumstats"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

type cmdOption struct {
	Interface string `short:"i" long:"interface" description:"Read packets from the interface" value-name:"<interface>"`
	ReadFile  string `short:"r" long:"read"      description:"Read packets from the pcap file" hidden:"true"`
	InfluxDB  string `short:"d" long:"influxdb"  description:"Write packets to InfluxDB" value-name:"<url>" default:"http://localhost:8086"`
	Interval  uint   `short:"t" long:"interval"  description:"Interval time in sec to record" value-name:"<interval>" default:"3"`
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

func (c *cmdOption) BlackHoleConfig() *vplsbh.BlackHoleConfig {
	return &vplsbh.BlackHoleConfig{
		Interface: c.Interface,
		ReadFile:  c.ReadFile,
	}
}

type VPLSPacketTags struct {
	Domain, Remote, Protocol, Type, Length string
}

func recordBUMStats(db influx.Client, interval uint, ch chan *VPLSPacketTags) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	bpcfg := influx.BatchPointsConfig{Database: Database, Precision: "s"}
	count := make(map[VPLSPacketTags]uint)

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

				pt, _ := influx.NewPoint(Series, tags, fields)
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
	// MPLS Decoder should assume that the MPLS payload is a Ethenet frame with a control-word header
	layers.MPLSPayloadDecoder = &l2vpn.PWMCWDecoder{ControlWord: true}

	opt, err := NewCmdOption(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	b, err := vplsbh.NewBlackHole(opt.BlackHoleConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer b.Close()

	db, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: opt.InfluxDB})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	ch := make(chan *VPLSPacketTags, 1000)
	defer close(ch)

	go recordBUMStats(db, opt.Interval, ch)

	for packet := range b.Packets() {
		var typeString, lengthString string

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)

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

		ch <- &VPLSPacketTags{
			Domain:   packet.Domain,
			Remote:   packet.Remote,
			Type:     typeString,
			Length:   lengthString,
			Protocol: eth.EthernetType.String(),
		}
	}
}
