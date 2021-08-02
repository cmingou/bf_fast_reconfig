package main

import (
	"container/ring"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/tools/go/ssa/interp/testdata/src/errors"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	wgp sync.WaitGroup

	sendPort string
	rcvPort  string

	emulator   bool
	serverMode bool
	clientMode bool
	verbose    bool

	snapshot_len int32 = 1520
	promiscuous  bool  = true
	err          error
	timeout      time.Duration = time.Millisecond
	sendHandle   *pcap.Handle
	rcvHandle    *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions

	report *TestReport
	end    = make(chan struct{})

	SendPacketNumber uint64
)

func init() {
	flag.StringVar(&sendPort, "sendp", "en0", "port to send packet")
	flag.StringVar(&rcvPort, "rcvp", "en0", "port to receive packet")
	flag.BoolVar(&emulator, "e", false, "emulate mode")
	flag.BoolVar(&serverMode, "s", false, "server mode")
	flag.BoolVar(&clientMode, "c", false, "client mode")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.Uint64Var(&SendPacketNumber, "n", 0, "packet number to send")
	flag.Parse()

	report = new(TestReport)
	report.Ring = ring.New(5)
}

type TestReport struct {
	Duration      float64
	IndexPacketA  uint64
	IndexPacketB  uint64
	LastTimeStamp float64

	Tx uint64
	Rx uint64

	PacketA *TFTimestampLayer
	PacketB *TFTimestampLayer

	Ring *ring.Ring
}

func (t *TestReport) ToString() (str string) {
	if t.Rx != 0 {
		//str += fmt.Sprintln(t.PacketA.ToString())
		//str += fmt.Sprintln(t.PacketB.ToString())
		str += fmt.Sprintf("\rThe max gap happend between %d and %d... Max time duration: %.9f... Tx: %v... Rx: %v",
			t.IndexPacketA-1, t.IndexPacketA, t.Duration, t.Tx, t.Rx)
		//str += fmt.Sprintf("%-20s: %4.9f \n", "Max time duration", t.Duration)
		//str += fmt.Sprintf("%-20s: %d \n", "Tx", t.Tx)
		//str += fmt.Sprintf("%-20s: %d \n", "Rx", t.Rx)
	}
	return str
}

type TFTimestampLayer struct {
	index         uint64
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

func sendPacket() {
	var i uint64
	if SendPacketNumber == 0 {
		for {
			select {
			case <-end:
				break
			default:
				sendUDPPacket(i + 1)
				report.Tx++
				i++
			}
		}
	} else {
		for i = 0; i < SendPacketNumber; i++ {
			sendUDPPacket(i + 1)
			report.Tx++
		}
		wgp.Done()
	}

	report.Tx++
}

func sendUDPPacket(index uint64) {
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()

	// This time lets fill out some information
	//ETH: Length 14
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x50, 0x6b, 0x4b, 0xd3, 0xd5, 0x25},
		DstMAC:       net.HardwareAddr{0x98, 0x03, 0x9b, 0x1d, 0x62, 0xc1},
		EthernetType: layers.EthernetTypeIPv4,
	}

	//IP: Length 20
	ipLayer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     76,
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
		Length:    56,
	}

	if emulator {
		tFTimestampLayer := &TFTimestampLayer{
			index:         index,
			ingressMac:    []byte{0x00, 0x30, 0xa3, 0xc4, 0x96, 0x80},
			ingressGlobal: []byte{0x00, 0x30, 0xa3, 0xc4, 0x96, 0x80},
			enqueue:       []byte{0x00, 0x00, 0x00, 0x01},
			dequeueDelta:  []byte{0x00, 0x00, 0x00, 0x01},
			egressGlobal:  []byte{0x00, 0x30, 0xa4, 0x3e, 0xa8, 0x80},
			egressTx:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}

		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer,
			udpLayer,
			gopacket.Payload(tFTimestampLayer.LayerContents()),
		)
	} else {
		tFTimestampLayer := &TFTimestampLayer{
			index:         index,
			ingressMac:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			ingressGlobal: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			enqueue:       []byte{0x00, 0x00, 0x00, 0x00},
			dequeueDelta:  []byte{0x00, 0x00, 0x00, 0x00},
			egressGlobal:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			egressTx:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}

		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer,
			udpLayer,
			gopacket.Payload(tFTimestampLayer.LayerContents()),
		)
	}

	outgoingPacket := buffer.Bytes()
	if index%1000 == 0 {
		fmt.Printf("Sending %d th packet\n", index)
	}
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
		//fmt.Println("Trouble decoding layers: ", err)
	}

	for _, layerType := range foundLayerTypes {
		if layerType == layers.LayerTypeEthernet {
			//fmt.Println("Ethernet: ", ethLayer.SrcMAC, "->", ethLayer.DstMAC)
		}
		if layerType == layers.LayerTypeIPv4 {
			//fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
		}
		if layerType == layers.LayerTypeUDP {
			//fmt.Printf("UDP Port: %v -> %v, length: %v\n", udpLayer.SrcPort, udpLayer.DstPort, udpLayer.Length)
			if udpLayer.Payload != nil {
				if e := tFTimesLayer.DecodeFromBytes(udpLayer.Payload, nil); e == nil {

					// Print Packet info
					if verbose && (int(tFTimesLayer.index)%1000 == 0) {
						fmt.Println("Tofino/Tofino2 Timestamp header")
						fmt.Println(tFTimesLayer.ToString())
					}

					// Calculate time slot
					if report.LastTimeStamp != 0 {
						timeDuration := tFTimesLayer.IngressMacTime() - report.LastTimeStamp
						if timeDuration > report.Duration {
							report.Duration = timeDuration
							report.IndexPacketA = tFTimesLayer.index

							report.PacketA = report.Ring.Prev().Value.(*TFTimestampLayer)
							report.PacketB = &tFTimesLayer
						}
						report.LastTimeStamp = tFTimesLayer.IngressMacTime()
					} else {
						report.LastTimeStamp = tFTimesLayer.IngressMacTime()
						report.IndexPacketA = tFTimesLayer.index
					}

					report.Ring.Value = &tFTimesLayer
					report.Ring = report.Ring.Next()

				} else {
					fmt.Printf("Parse TFTimestamp layer failed, err: %v\n", e)
				}
			}
		}
	}
}

func rcvPacket() {
	packetSource := gopacket.NewPacketSource(rcvHandle, rcvHandle.LinkType())
	for packet := range packetSource.Packets() {
		report.Rx++
		if verbose && (report.Rx%1000 == 0) {
			fmt.Printf("Receive %d th packets\n", report.Rx)
		}
		pakcetInfo(packet)
	}
}

func main() {
	if !serverMode && !clientMode {
		fmt.Printf("Please choose server mode or client mode\n")
	} else if serverMode {

		fmt.Printf("Server(Receiver) started!\n")

		// server mode(Receiver)
		rcvInteractiveHandle, err := pcap.NewInactiveHandle(rcvPort)
		if err != nil {
			log.Fatal(err)
		}
		defer rcvInteractiveHandle.CleanUp()

		if err = rcvInteractiveHandle.SetTimeout(time.Nanosecond); err != nil {
			log.Fatal(err)
		}

		rcvHandle, err = rcvInteractiveHandle.Activate() // after this, inactive is no longer valid
		if err != nil {
			log.Fatal(err)
		}
		defer rcvHandle.Close()

		//// Set filter
		//var filter string = "udp and host 1.1.1.1"
		//err = rcvHandle.SetBPFFilter(filter)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//fmt.Println("Filter with: ", filter)

		wgp.Add(1)
		go rcvPacket()

		go func() {
			//var currentIteration, lastCount int
			printInterval := 1 * time.Second
			ticker := time.Tick(printInterval)
			for {
				select {
				case <-end:
					break
				case <-ticker:
					fmt.Printf("\033[2K\r%v", report.ToString())
					//currentIteration, iterations, float64(currentIteration-lastCount)/printInterval.Seconds())
					//lastCount = currentIteration
				}
			}
		}()
	} else {
		// client mode(Sender)
		sendInteractiveHandle, err := pcap.NewInactiveHandle(sendPort)
		if err != nil {
			log.Fatal(err)
		}
		defer sendInteractiveHandle.CleanUp()

		if err = sendInteractiveHandle.SetTimeout(time.Nanosecond); err != nil {
			log.Fatal(err)
		}

		sendHandle, err = sendInteractiveHandle.Activate() // after this, inactive is no longer valid
		if err != nil {
			log.Fatal(err)
		}
		defer sendHandle.Close()

		time.Sleep(time.Second * 1)
		wgp.Add(1)
		go sendPacket()
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n- Ctrl+C pressed in Terminal\n")
		if clientMode {
			end <- struct{}{}
		}
		fmt.Println(report.PacketA.ToString())
		fmt.Println(report.PacketB.ToString())
		os.Exit(0)
	}()

	wgp.Wait()
}
