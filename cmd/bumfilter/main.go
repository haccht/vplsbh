package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/haccht/vplsbh/cache"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/gomodule/redigo/redis"
	"github.com/jessevdk/go-flags"
)

const (
	PCAP_SNAPSHOT_LEN = 65536
	PCAP_PROMISCUOUS  = true

	REDIS_URL = "redis://localhost:6379"
)

type tuple struct {
	Domain, Remote, SrcMAC string
}

type Monitor struct {
	mo     *MonitorOption
	c1     *cache.TTLCache // In-memory KVS to map MPLS Label     -> Domain, Remote
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
		val, err := redis.Values(conn.Do("HMGET", key, "Domain", "Remote"))
		if err != nil {
			return nil, false
		}

		t := &tuple{}
		if _, err := redis.Scan(val, &t.Domain, &t.Remote); err != nil {
			return nil, false
		}

		m.c1.SetWithExpiration(k, t, cache.DefaultExpiration)
		return t, true
	})

	return m
}

type MonitorOption struct {
	PcapFile  string `short:"f" long:"file"       description:"Read packets from the pcap file" hidden:"true"`
	Interface string `short:"i" long:"interface"  description:"Read packets from the interface"`
	Domain    string `short:"d" long:"domain"     description:"Filter packets by Domain name"`
	BPFFilter string `short:"e" long:"expression" description:"Filter packets by BPF primitive"`
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

	return pcap.OpenLive(m.mo.Interface, PCAP_SNAPSHOT_LEN, PCAP_PROMISCUOUS, 3*time.Second)
}

func (m *Monitor) Write(ch <-chan gopacket.Packet) {
	for packet := range ch {
		m.logger.Println(packet)
	}
}

func (m *Monitor) Read(ch chan<- gopacket.Packet) error {
	var eth layers.Ethernet
	var vpls l2vpn.VPLS
	var pwmcw l2vpn.PWMCW
	var parser *gopacket.DecodingLayerParser

	handle, err := m.OpenPcapHandle()
	if err != nil {
		return fmt.Errorf("Could not open the pcap handle.\n%s", err.Error())
	}
	defer handle.Close()

	var bpf *pcap.BPF
	if m.mo.BPFFilter != "" {
		bpf, err = pcap.NewBPF(layers.LinkTypeEthernet, PCAP_SNAPSHOT_LEN, m.mo.BPFFilter)
		if err != nil {
			m.logger.Printf("Error compiling BPF filter: %s", err)
		}
	}

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

		ethdata := append(eth.Contents, eth.Payload...)

		if m.mo.BPFFilter != "" {
			ci := gopacket.CaptureInfo{CaptureLength: len(ethdata), Length: len(ethdata)}
			if !bpf.Matches(ci, ethdata) {
				continue
			}
		}

		if m.mo.Domain != "" {
			if v, ok := m.c1.Get(vpls.Label); ok {
				t := v.(*tuple)
				if m.mo.Domain != t.Domain {
					continue
				}
			}
		}

		ch <- gopacket.NewPacket(ethdata, layers.LayerTypeEthernet, gopacket.Default)
	}
}

func (m *Monitor) Run() error {
	ch := make(chan gopacket.Packet, 1000)
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
