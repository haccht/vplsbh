package l2vpn

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypePWMCW = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{Name: "PWMCW", Decoder: gopacket.DecodeFunc(decodePWMCW)})

type PWMCW struct {
	SequenceNumber uint32
	layers.BaseLayer
}

func (cw *PWMCW) LayerType() gopacket.LayerType {
	return LayerTypePWMCW
}

func (cw *PWMCW) CanDecode() gopacket.LayerClass {
	return LayerTypePWMCW
}

func (cw *PWMCW) NextLayerType() gopacket.LayerType {
	return layers.LayerTypeEthernet
}

func (cw *PWMCW) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(bytes, cw.SequenceNumber)
	return nil
}

func (cw *PWMCW) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if data[0]&0xF0 != 0 {
		return fmt.Errorf("PW MPLS Control Word is missing")
	}

	cw.SequenceNumber = binary.BigEndian.Uint32(data)
	cw.BaseLayer = layers.BaseLayer{data[:4], data[4:]}
	return nil
}

func decodePWMCW(data []byte, p gopacket.PacketBuilder) error {
	cw := &PWMCW{}

	err := cw.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(cw)
	return p.NextDecoder(layers.LayerTypeEthernet)
}

type PWMCWDecoder struct {
	ControlWord bool
}

func (c *PWMCWDecoder) Decode(data []byte, p gopacket.PacketBuilder) error {
	if c.ControlWord {
		return decodePWMCW(data, p)
	}

	return p.NextDecoder(layers.LayerTypeEthernet)
}
