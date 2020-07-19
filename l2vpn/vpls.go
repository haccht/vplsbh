package l2vpn

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeVPLS = gopacket.RegisterLayerType(1024, gopacket.LayerTypeMetadata{Name: "VPLS", Decoder: gopacket.DecodeFunc(decodeVPLS)})

type VPLS layers.MPLS

func (v *VPLS) LayerType() gopacket.LayerType {
	return layers.LayerTypeMPLS
}

func (v *VPLS) NextLayerType() gopacket.LayerType {
	return LayerTypePWMCW
}

func (v *VPLS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	decoded := binary.BigEndian.Uint32(data[:4])

	v.Label = decoded >> 12
	v.TrafficClass = uint8(decoded>>9) & 0x7
	v.StackBottom = decoded&0x100 != 0
	v.TTL = uint8(decoded)
	v.BaseLayer = layers.BaseLayer{data[:4], data[4:]}

	return nil
}

func decodeVPLS(data []byte, p gopacket.PacketBuilder) error {
	vpls := &VPLS{}
	err := vpls.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(vpls)

	if vpls.StackBottom {
		return p.NextDecoder(layers.MPLSPayloadDecoder)
	}

	return p.NextDecoder(gopacket.DecodeFunc(decodeVPLS))
}

func (v *VPLS) CanDecode() gopacket.LayerClass {
	return v.LayerType()
}
