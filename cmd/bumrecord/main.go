package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"time"

	"github.com/haccht/vplsbh/cache"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/gomodule/redigo/redis"
	"github.com/jessevdk/go-flags"

	_ "github.com/influxdata/influxdb1-client"
	influx "github.com/influxdata/influxdb1-client/v2"
)

const (
	PCAP_SNAPSHOT_LEN = 65536
	PCAP_PROMISCUOUS  = true

	REDIS_URL = "redis://localhost:6379"

	INFLUXDB_URL      = "http://localhost:8086"
	INFLUXDB_DATABASE = "vplsbh"
	INFLUXDB_SERIES   = "bumrecord"
)

type tuple struct {
	Domain, PeerID, SrcMAC string
}

type Monitor struct {
	mo     *MonitorOption
	c1     *cache.TTLCache // In-memory KVS to map MPLS Label     -> Domain, PeerID
	logger *log.Logger
}

func NewMonitor(mo *MonitorOption) *Monitor {
	m := &Monitor{
		mo:     mo,
		c1:     cache.NewTTLCache(5 * time.Minute),
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	r := &redis.Pool{
		MaxIdle:     2,
		MaxActive:   4,
		IdleTimeout: 5 * time.Minute,
		Dial:        func() (redis.Conn, error) { return redis.DialURL(REDIS_URL) },
	}

	// Set a lookup function used when the key would not be found or be expired.
	m.c1.SetLookupFunc(func(k interface{}) (interface{}, bool) {
		conn := r.Get()
		defer conn.Close()

		key := fmt.Sprintf("label:%d", k)
		val, err := redis.Values(conn.Do("HMGET", key, "Domain", "PeerID"))
		if err != nil {
			return nil, false
		}

		t := &tuple{}
		if _, err := redis.Scan(val, &t.Domain, &t.PeerID); err != nil {
			return nil, false
		}

		m.c1.SetWithExpiration(k, t, cache.DefaultExpiration)
		return t, true
	})

	return m
}

type MonitorOption struct {
	PcapFile  string `short:"f" long:"file"      description:"Read packets from the pcap file" hidden:"true"`
	Interface string `short:"i" long:"interface" description:"Read packets from the interface"`
	Interval  uint   `short:"t" long:"interval"  description:"Interval time in sec to record" default:"3"`
	Verbose   bool   `short:"v" long:"verbose"   description:"Show verbose information"`
}

func NewMonitorOption(args []string) (*MonitorOption, error) {
	mo := &MonitorOption{}

	_, err := flags.ParseArgs(mo, args)
	if err != nil {
		if err != flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		return nil, err
	}

	if mo.Interface == "" && mo.PcapFile == "" {
		return nil, errors.New("the flag `--interface` was not specified")
	}

	return mo, nil
}

func (m *Monitor) OpenPcapHandle() (*pcap.Handle, error) {
	if m.mo.PcapFile != "" {
		return pcap.OpenOffline(m.mo.PcapFile)
	}

	return pcap.OpenLive(m.mo.Interface, PCAP_SNAPSHOT_LEN, PCAP_PROMISCUOUS, pcap.BlockForever)
}

func (m *Monitor) Write(ch <-chan map[string]string) {
	db, err := influx.NewHTTPClient(influx.HTTPConfig{Addr: INFLUXDB_URL})
	if err != nil {
		m.logger.Printf("Could not connect to InfluxDB: %s", err.Error())
		return
	}
	defer db.Close()

	tick := time.NewTicker(time.Duration(m.mo.Interval) * time.Second)
	conf := influx.BatchPointsConfig{Database: INFLUXDB_DATABASE, Precision: "s"}

	bp, _ := influx.NewBatchPoints(conf)
	for {
		select {
		case tags, ok := <-ch:
			if !ok {
				tick.Stop()
				return
			}

			fields := map[string]interface{}{"event": 1}
			pt, _ := influx.NewPoint(INFLUXDB_SERIES, tags, fields)
			bp.AddPoint(pt)
		case <-tick.C:
			if err = db.Write(bp); err != nil {
				m.logger.Printf("Could not write points to InfluxDB: %s", err.Error())
			} else if m.mo.Verbose {
				m.logger.Printf("Dump %d points to InfluxDB.", len(bp.Points()))
			}
			bp, _ = influx.NewBatchPoints(conf)
		}
	}
}

func (m *Monitor) Read(ch chan<- map[string]string) error {
	var eth layers.Ethernet
	var vpls l2vpn.VPLS
	var pwmcw l2vpn.PWMCW
	var parser *gopacket.DecodingLayerParser

	handle, err := m.OpenPcapHandle()
	if err != nil {
		return fmt.Errorf("Could not open the pcap handle.\n%s", err.Error())
	}
	defer handle.Close()

	decoded := make([]gopacket.LayerType, 0, 3)

	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			m.logger.Printf("Error reading packet data: %s", err)
			continue
		}

		// Remove the outer Ethernet layer
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth)
		parser.DecodeLayers(data, &decoded)

		// Parse the VPLS and inner Ethernet layers
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeMPLS, &vpls, &pwmcw, &eth)
		parser.DecodeLayers(eth.Payload, &decoded)

		if len(decoded) < 3 ||
			decoded[0] != layers.LayerTypeMPLS ||
			decoded[1] != l2vpn.LayerTypePWMCW ||
			decoded[2] != layers.LayerTypeEthernet {
			continue
		}

		v, ok := m.c1.Get(vpls.Label)
		if !ok {
			continue
		}
		t := v.(*tuple)

		tags := map[string]string{
			"domain":   t.Domain,
			"protocol": eth.EthernetType.String(),
		}

		// Broadcast, Multicast, Unknown-Unicast
		switch {
		case reflect.DeepEqual(eth.DstMAC, layers.EthernetBroadcast):
			tags["type"] = "broadcast"
		case eth.DstMAC[0]&0x01 == 1: //I/G bit
			tags["type"] = "multicast"
		default:
			tags["type"] = "unicast"
		}

		// Frame size (include FCS)
		length := len(eth.Contents) + len(eth.Payload) + 4
		switch {
		case length < 128:
			tags["length"] = "64-127"
		case length < 256:
			tags["length"] = "128-255"
		case length < 512:
			tags["length"] = "256-511"
		case length < 1024:
			tags["length"] = "512-1023"
		case length < 1519:
			tags["length"] = "1024-1518"
		default:
			tags["length"] = "1519-"
		}

		ch <- tags
	}
}

func (m *Monitor) Run() error {
	ch := make(chan map[string]string, 1000)
	defer close(ch)

	go m.Write(ch)
	return m.Read(ch)
}

func main() {
	// MPLS Decoder should assume that the MPLS payload is a Ethenet frame with a control-word header
	layers.MPLSPayloadDecoder = &l2vpn.PWMCWDecoder{ControlWord: true}

	mo, err := NewMonitorOption(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	m := NewMonitor(mo)
	if err = m.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
