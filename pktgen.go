package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	wg sync.WaitGroup

	device       string = "en0"
	sendPort     string = "en0"
	rcvPort      string = "en0"
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	sendHandle   *pcap.Handle
	rcvHandle    *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

type TFTimestampLayer struct {
	ingressMac    []byte
	ingressGlobal []byte
	enqueue       []byte
	dequeueDelta  []byte
	egressGlobal  []byte
	egressTx      []byte
}

var TFTimestampLayerType = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		Name:    "TFTimestampLayer",
		Decoder: gopacket.DecodeFunc(decodeTFTimestampLayer),
	},
)

func (l *TFTimestampLayer) String() string {
	var str string
	var ns float64 = 1000000000
	str = fmt.Sprintf("%-35s: %30.9fs\n", "Ingress mac", float64(binary.BigEndian.Uint64(l.ingressMac))/ns)
	str += fmt.Sprintf("%-35s: %30.9fs\n", "Ingress global", float64(binary.BigEndian.Uint64(l.ingressGlobal))/ns)
	str += fmt.Sprintf("%-35s: %30.9fs\n", "Traffic Manager enqueue", float64(binary.BigEndian.Uint32(l.enqueue))/ns)
	str += fmt.Sprintf("%-35s: %30.9fs\n", "Traffic Manager dequeue delta", float64(binary.BigEndian.Uint32(l.dequeueDelta))/ns)
	str += fmt.Sprintf("%-35s: %30.9fs\n", "Egress global", float64(binary.BigEndian.Uint64(l.egressGlobal))/ns)
	str += fmt.Sprintf("%-35s: %30.9fs\n", "Egress TX(no value in model)", float64(binary.BigEndian.Uint64(l.egressTx))/ns)

	return str
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
	return c
}

func (l *TFTimestampLayer) LayerPayload() []byte {
	return []byte{}
}

func (l *TFTimestampLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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

func sendUDPPacket() {
	// This time lets fill out some information
	//ETH: Length 14
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		DstMAC:       net.HardwareAddr{0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
		EthernetType: layers.EthernetTypeIPv4,
	}

	//IP: Length 20
	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     33,
		Id:         101,
		Flags:      layers.IPv4DontFragment,
		FragOffset: 0,
		TTL:        64,
		Protocol:   layers.IPProtocolUDP,
		SrcIP:      net.IP{1, 1, 1, 1},
		DstIP:      net.IP{2, 2, 2, 2},
	}

	//UDP: Length 8
	udpLayer := &layers.UDP{
		BaseLayer: layers.BaseLayer{},
		SrcPort:   layers.UDPPort(4321),
		DstPort:   layers.UDPPort(80),
		Length:    13,
	}
	//rawBytes := []byte{'h', 'e', 'l', 'l', 'o'}

	tFTimestampLayer := &TFTimestampLayer{
		ingressMac:    []byte{0x00, 0x30, 0xa3, 0xc4, 0x96, 0x80},
		ingressGlobal: []byte{0x00, 0x30, 0xa3, 0xc4, 0x96, 0x80},
		enqueue:       []byte{0x00, 0x00, 0x00, 0x01},
		dequeueDelta:  []byte{0x00, 0x00, 0x00, 0x01},
		egressGlobal:  []byte{0x00, 0x30, 0xa4, 0x3e, 0xa8, 0x80},
		egressTx:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(tFTimestampLayer.LayerContents()),
	)

	outgoingPacket := buffer.Bytes()
	err = sendHandle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func pakcetInfo(packet gopacket.Packet) {
	var (
		ethLayer     layers.Ethernet
		ipLayer      layers.IPv4
		udpLayer     layers.UDP
		tFTimesLayer TFTimestampLayer
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&udpLayer,
	)
	foundLayerTypes := []gopacket.LayerType{}
	err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
	if err != nil {
		fmt.Println("Trouble decoding layers: ", err)
	}

	for _, layerType := range foundLayerTypes {
		if layerType == layers.LayerTypeIPv4 {
			fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
		}
		if layerType == layers.LayerTypeUDP {
			fmt.Println("UDP Port: ", udpLayer.SrcPort, "->", udpLayer.DstPort)
			fmt.Println("Length:", udpLayer.Length)

			if udpLayer.Payload != nil {
				tFTimesLayer.DecodeFromBytes(udpLayer.Payload, nil)
				fmt.Println("Tofino/Tofino2 Timestamp header")

				fmt.Println(tFTimesLayer.String())
			}
		}
	}
}

func rcvUDPPacket() {
	packetSource := gopacket.NewPacketSource(rcvHandle, rcvHandle.LinkType())
	for packet := range packetSource.Packets() {
		pakcetInfo(packet)
	}
}

func main() {

	// Open device
	sendHandle, err = pcap.OpenLive(sendPort, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer sendHandle.Close()

	rcvHandle, err = pcap.OpenLive(rcvPort, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer rcvHandle.Close()

	// Set filter
	var filter string = "udp and host 1.1.1.1"
	err = rcvHandle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP packets.")

	wg.Add(1)
	go rcvUDPPacket()
	time.Sleep(time.Second * 1)
	sendUDPPacket()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		os.Exit(0)
	}()

	wg.Wait()
}
