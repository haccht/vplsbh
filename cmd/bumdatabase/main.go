package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/haccht/vplsbh"
	"github.com/haccht/vplsbh/l2vpn"

	"github.com/google/gopacket/layers"
	"github.com/jessevdk/go-flags"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)
)

type cmdOption struct {
	Interface string `short:"i" long:"interface" description:"Read packets from the interface" value-name:"<interface>"`
	ReadFile  string `short:"r" long:"read"      description:"Read packets from the pcap file" hidden:"true"`
	RedisURL  string `short:"d" long:"redis"     description:"Record packets to ForwardingDB" value-name:"<url>" default:"redis://localhost:6379"`
	AgingTime uint   `short:"e" long:"expire"    description:"Aging time in sec to record" value-name:"<interval>" default:"300"`
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

func record(db redis.Conn, ch chan *VPLSFDBEntry, agingtime, interval uint) {
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	entries := make(map[string]*VPLSFDBEntry)

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				tick.Stop()
				return
			}

			key := fmt.Sprintf("entry:%s:%s", e.Domain, e.SrcMAC)
			entries[key] = e
		case <-tick.C:
			var err error

			err = db.Send("MULTI")
			if err != nil {
				continue
			}

			for key, e := range entries {
				db.Do("HMSET", key, "Domain", e.Domain, "SrcMAC", e.SrcMAC, "Remote", e.Remote)
				db.Do("EXPIRE", key, agingtime)

				delete(entries, key)
			}

			_, err = db.Do("EXEC")
			if err != nil {
				continue
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

	ch := make(chan *VPLSFDBEntry, 1000)
	defer close(ch)

	db, err := redis.DialURL(opt.RedisURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()

	logger.Printf("Start capturing packets")
	go record(db, ch, opt.AgingTime, opt.Interval)

	for packet := range b.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		eth, _ := ethLayer.(*layers.Ethernet)

		ch <- &VPLSFDBEntry{SrcMAC: eth.SrcMAC.String(), Domain: packet.Domain, Remote: packet.Remote}
	}
}
