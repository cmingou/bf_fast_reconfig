package pktgen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
)

var (
	TFTimestampLayerType = gopacket.RegisterLayerType(
		2002,
		gopacket.LayerTypeMetadata{
			Name:    "TFTimestampLayer",
			Decoder: gopacket.DecodeFunc(decodeTFTimestampLayer),
		},
	)
)

type TFTimestampLayer struct {
	index         uint64
	ingressMac    []byte
	ingressGlobal []byte
	enqueue       []byte
	dequeueDelta  []byte
	egressGlobal  []byte
	egressTx      []byte
}

func (l *TFTimestampLayer) ToString() (str string) {
	var ns float64 = 1000000000

	str += fmt.Sprintf("%-35s: %30d\n", "Packet index", l.index)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Ingress mac", float64(binary.BigEndian.Uint64(l.ingressMac))/ns)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Ingress global", float64(binary.BigEndian.Uint64(l.ingressGlobal))/ns)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Traffic Manager enqueue", float64(binary.BigEndian.Uint32(l.enqueue))/ns)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Traffic Manager dequeue delta", float64(binary.BigEndian.Uint32(l.dequeueDelta))/ns)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Egress global", float64(binary.BigEndian.Uint64(l.egressGlobal))/ns)
	str += fmt.Sprintf("%-35s: %30.9f s\n", "Egress TX(no value in model)", float64(binary.BigEndian.Uint64(l.egressTx))/ns)
	return str
}

func (l *TFTimestampLayer) IngressMacTime() float64 {
	var ns float64 = 1000000000

	return float64(binary.BigEndian.Uint64(l.ingressMac)) / ns
}

func (l *TFTimestampLayer) LayerType() gopacket.LayerType {
	return TFTimestampLayerType
}

func (l *TFTimestampLayer) LayerContents() []byte {
	var c []byte

	c = append(c, []byte{0x00, 0x00}...)
	c = append(c, l.ingressMac...)
	c = append(c, []byte{0x00, 0x00}...)
	c = append(c, l.ingressGlobal...)
	c = append(c, l.enqueue...)
	c = append(c, l.dequeueDelta...)
	c = append(c, []byte{0x00, 0x00}...)
	c = append(c, l.egressGlobal...)
	c = append(c, []byte{0x00, 0x00}...)
	c = append(c, l.egressTx...)

	indexBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(indexBytes, l.index)
	c = append(c, indexBytes...)

	return c
}

func (l *TFTimestampLayer) LayerPayload() []byte {
	return []byte{}
}

func (l *TFTimestampLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 40 {
		return errors.New("Length is not enough to parsed")
	}
	//_ = data[0:2]
	l.ingressMac = data[0:8]
	//_ = data[8:10]
	l.ingressGlobal = data[8:16]
	l.enqueue = data[16:20]
	l.dequeueDelta = data[20:24]
	//_ = data[24:26]
	l.egressGlobal = data[24:32]
	//_ = data[32:34]
	l.egressTx = data[32:40]
	l.index = binary.BigEndian.Uint64(data[40:48])

	return nil
}

func (l *TFTimestampLayer) CanDecode() gopacket.LayerClass {
	return TFTimestampLayerType
}

func (l *TFTimestampLayer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (l *TFTimestampLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	panic("implement me")
}

func decodeTFTimestampLayer(data []byte, p gopacket.PacketBuilder) error {
	p.AddLayer(&TFTimestampLayer{
		ingressMac:    data[2:8],
		ingressGlobal: data[10:16],
		enqueue:       data[16:20],
		dequeueDelta:  data[20:24],
		egressGlobal:  data[26:32],
		egressTx:      data[34:40],
	})
	return p.NextDecoder(gopacket.LayerTypePayload)
}
