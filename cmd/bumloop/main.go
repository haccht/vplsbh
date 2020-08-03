package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/haccht/vplsbh"
	"github.com/haccht/vplsbh/cache"
	"github.com/haccht/vplsbh/l2vpn"
	"github.com/jessevdk/go-flags"

	"github.com/google/gopacket/layers"

	_ "github.com/influxdata/influxdb1-client"
	influx "github.com/influxdata/influxdb1-client/v2"
)

const (
	Database = "vplsbh"
	Series   = "bumloop"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

type cmdOption struct {
	Interface string `short:"i" long:"interface" description:"Read packets from the interface" value-name:"<interface>"`
	ReadFile  string `short:"r" long:"read"      description:"Read packets from the pcap file" hidden:"true"`
	InfluxDB  string `short:"d" long:"influxdb"  description:"Write packets to InfluxDB" value-name:"<url>" default:"http://localhost:8086"`
	Interval  uint   `short:"t" long:"interval"  description:"Interval time in sec to record" value-name:"<interval>" default:"3"`
	Verbose   bool   `short:"v" long:"verbose"   description:"Show verbose information"`
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

type VPLSFDBEntry struct {
	Domain, Remote, SrcMAC string
}

func recordLoopDetect(db influx.Client, interval uint, ch chan *VPLSFDBEntry) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	bpcfg := influx.BatchPointsConfig{Database: Database, Precision: "s"}
	count := make(map[VPLSFDBEntry]int)

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

	ch := make(chan *VPLSFDBEntry, 1000)
	defer close(ch)

	go recordLoopDetect(db, opt.Interval, ch)

	fdb := cache.NewTTLCache(12 * time.Hour) // In-memory KVS to map Domain, SrcMAC -> Domain, Remote, SrcMAC
	for packet := range b.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)

		key := VPLSFDBEntry{SrcMAC: eth.SrcMAC.String(), Domain: packet.Domain}
		val := VPLSFDBEntry{SrcMAC: eth.SrcMAC.String(), Domain: packet.Domain, Remote: packet.Remote}

		v, ok := fdb.Get(key)
		fdb.Set(key, &val)
		if !ok {
			continue
		}

		// Get the last learned Domain, Remote and SrcMAC and check if the Remote has changed
		learned := v.(*VPLSFDBEntry)
		if packet.Domain == learned.Domain && packet.Remote != learned.Remote {
			if opt.Verbose {
				logger.Printf("Domain=%s DstMAC=%s SrcMAC=%s Remote=%s, previously learned from Remote=%s",
					packet.Domain, eth.DstMAC, eth.SrcMAC, packet.Remote, learned.Remote)
			}
			ch <- &val
		}
	}
}
