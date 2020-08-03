package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/haccht/vplsbh"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/jessevdk/go-flags"
)

type cmdOption struct {
	Interface    string `short:"i" long:"interface" description:"Read packets from the interface" value-name:"<interface>"`
	ReadFile     string `short:"r" long:"read"      description:"Read packets from the pcap file" hidden:"true"`
	WriteFile    string `short:"w" long:"write"     description:"Write packets to the pcap file" value-name:"<filepath>"`
	BPFFilter    string `short:"e" long:"bpf"       description:"Filter packets by BPF primitive" value-name:"<expression>"`
	DomainFilter string `short:"d" long:"domain"    description:"Filter packets by Bridge-Domain name" value-name:"<bdname>"`
	PacketCount  uint   `short:"c" long:"count"     description:"Exit after reading specified number of packets" value-name:"<count>"`
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
		Interface:    c.Interface,
		ReadFile:     c.ReadFile,
		PacketCount:  c.PacketCount,
		BPFFilter:    c.BPFFilter,
		DomainFilter: c.DomainFilter,
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

	var w *pcapgo.Writer
	if opt.WriteFile != "" {
		f, err := os.Create(opt.WriteFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()

		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(vplsbh.SnapshotLen, layers.LinkTypeEthernet)
	}

	for packet := range b.Packets() {
		fmt.Println(packet)
		if w != nil {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}
