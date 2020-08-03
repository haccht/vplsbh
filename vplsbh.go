package vplsbh

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/haccht/vplsbh/cache"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/gomodule/redigo/redis"
)

const (
	RedisURL    = "redis://localhost:6379"
	SnapshotLen = 65536
)

type BlackHoleConfig struct {
	Interface    string
	ReadFile     string
	PacketCount  uint
	BPFFilter    string
	DomainFilter string
}

func openPcapHandle(cfg *BlackHoleConfig) (*pcap.Handle, error) {
	if cfg.ReadFile != "" {
		return pcap.OpenOffline(cfg.ReadFile)
	}

	if cfg.Interface != "" {
		return pcap.OpenLive(cfg.Interface, SnapshotLen, true, pcap.BlockForever)
	}

	return nil, errors.New("Interface was not specified")
}

func makeBPFFilter(cfg *BlackHoleConfig) (*pcap.BPF, error) {
	if cfg.BPFFilter == "" {
		return nil, nil
	}

	return pcap.NewBPF(layers.LinkTypeEthernet, SnapshotLen, cfg.BPFFilter)
}

type VPLSPacket struct {
	gopacket.Packet

	Label  uint32
	Remote string
	Domain string
}

type BlackHole struct {
	cfg    *BlackHoleConfig
	bpf    *pcap.BPF
	tlv    *cache.TTLCache // In-memory KVS to map MPLS Label -> Domain, Remote
	handle *pcap.Handle
}

func NewBlackHole(cfg *BlackHoleConfig) (*BlackHole, error) {
	handle, err := openPcapHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("Could not open the pcap handle: %s", err.Error())
	}

	bpf, err := makeBPFFilter(cfg)
	if err != nil {
		return nil, fmt.Errorf("Could not make BPF filter: %s", err.Error())
	}

	b := &BlackHole{
		cfg:    cfg,
		bpf:    bpf,
		tlv:    cache.NewTTLCache(5 * time.Minute),
		handle: handle,
	}

	r := &redis.Pool{
		MaxIdle:     2,
		MaxActive:   4,
		IdleTimeout: 5 * time.Minute,
		Dial:        func() (redis.Conn, error) { return redis.DialURL(RedisURL) },
	}

	// Set a lookup function used when the key would not be found or be expired.
	b.tlv.SetLookupFunc(func(k interface{}) (interface{}, bool) {
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

		b.tlv.SetWithExpiration(k, t, cache.DefaultExpiration)
		return t, true
	})

	return b, nil
}

func (b *BlackHole) Close() {
	b.handle.Close()
}

func (b *BlackHole) Packets() chan *VPLSPacket {
	ch := make(chan *VPLSPacket, 1000)

	go func() {
		var np uint
		var eth layers.Ethernet
		var vpls l2vpn.VPLS
		var pwmcw l2vpn.PWMCW
		var parser *gopacket.DecodingLayerParser

		decoded := make([]gopacket.LayerType, 0, 3)
		for {
			data, ci, err := b.handle.ZeroCopyReadPacketData()
			switch {
			case err == io.EOF:
				return
			case err != nil:
				continue
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

			base := append(eth.Contents, eth.Payload...)
			baseci := gopacket.CaptureInfo{Timestamp: ci.Timestamp, CaptureLength: len(base), Length: len(base)}

			if b.bpf != nil {
				if !b.bpf.Matches(baseci, base) {
					continue
				}
			}

			v, ok := b.tlv.Get(vpls.Label)
			if !ok {
				continue
			}

			t := v.(*struct{ Domain, Remote string })
			if b.cfg.DomainFilter != "" && b.cfg.DomainFilter != t.Domain {
				continue
			}

			packet := &VPLSPacket{
				Packet: gopacket.NewPacket(base, layers.LayerTypeEthernet, gopacket.Lazy),
				Label:  vpls.Label,
				Domain: t.Domain,
				Remote: t.Remote,
			}

			m := packet.Metadata()
			m.CaptureInfo = baseci

			np++
			ch <- packet

			if b.cfg.PacketCount != 0 && b.cfg.PacketCount == np {
				close(ch)
				return
			}
		}
	}()

	return ch
}
