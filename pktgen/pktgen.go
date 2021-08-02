package pktgen

import (
	"container/ring"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/tools/go/ssa/interp/testdata/src/errors"
	"net"
	"time"
)

var (
	report = new(TestReport)
)

func init() {
	report.Ring = ring.New(5)
}

type PacketSender struct {
	Port string

	handle  *pcap.Handle
	buffer  gopacket.SerializeBuffer
	options gopacket.SerializeOptions

	end chan struct{}
}

func (r *PacketSender) Start() error {
	if r.Port == "" {
		return errors.New("Did not set receive interface")
	}

	fmt.Printf("Packet Sender started!\n")

	r.end = make(chan struct{})

	sendInteractiveHandle, err := pcap.NewInactiveHandle(r.Port)
	if err != nil {
		return err
	}
	defer sendInteractiveHandle.CleanUp()

	if err = sendInteractiveHandle.SetTimeout(time.Nanosecond); err != nil {
		return err
	}

	r.handle, err = sendInteractiveHandle.Activate() // after this, inactive is no longer valid
	if err != nil {
		return err
	}

	time.Sleep(time.Second * 1)

	go func() {
		report.Tx = 0

		for {
			select {
			case <-r.end:
				break
			default:
				report.Tx++
				// And create the packet with the layers
				r.buffer = gopacket.NewSerializeBuffer()

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

				tFTimestampLayer := &TFTimestampLayer{
					index:         report.Tx,
					ingressMac:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					ingressGlobal: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					enqueue:       []byte{0x00, 0x00, 0x00, 0x00},
					dequeueDelta:  []byte{0x00, 0x00, 0x00, 0x00},
					egressGlobal:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					egressTx:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				}

				gopacket.SerializeLayers(r.buffer, r.options,
					ethernetLayer,
					ipLayer,
					udpLayer,
					gopacket.Payload(tFTimestampLayer.LayerContents()),
				)

				outgoingPacket := r.buffer.Bytes()
				if err := r.handle.WritePacketData(outgoingPacket); err != nil {
					fmt.Printf("Failed to send packet, err: %v\n", err)
				}
			}
		}
	}()
	return nil
}

func (r *PacketSender) Stop() {
	r.end <- struct{}{}
	time.Sleep(2 * time.Second)
	r.handle.Close()
	fmt.Printf("Packet Sender stopped.\n")
}

type PacketReceiver struct {
	Port string

	handle       *pcap.Handle
	ethLayer     layers.Ethernet
	ipLayer      layers.IPv4
	udpLayer     layers.UDP
	tFTimesLayer TFTimestampLayer

	end chan struct{}
}

func (r *PacketReceiver) Start() error {
	if r.Port == "" {
		return errors.New("Did not set receive interface")
	}

	fmt.Printf("Packet Receiver started!\n")

	r.end = make(chan struct{})

	// server mode(Receiver)
	rcvInteractiveHandle, err := pcap.NewInactiveHandle(r.Port)
	if err != nil {
		return err
	}
	defer rcvInteractiveHandle.CleanUp()

	if err = rcvInteractiveHandle.SetTimeout(time.Nanosecond); err != nil {
		return err
	}

	r.handle, err = rcvInteractiveHandle.Activate() // after this, inactive is no longer valid
	if err != nil {
		return err
	}

	go func() {
		packetSource := gopacket.NewPacketSource(r.handle, r.handle.LinkType())

		for {
			select {
			case <-r.end:
				break
			case packet := <-packetSource.Packets():
				fmt.Printf("\rTx: %v... Rx: %v", report.Tx, report.Rx)
				report.Rx++

				parser := gopacket.NewDecodingLayerParser(
					layers.LayerTypeEthernet,
					&r.ethLayer,
					&r.ipLayer,
					&r.udpLayer,
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
						if r.udpLayer.Payload != nil {
							if e := r.tFTimesLayer.DecodeFromBytes(r.udpLayer.Payload, nil); e == nil {

								// Calculate time slot
								if report.LastTimeStamp != 0 {
									timeDuration := r.tFTimesLayer.IngressMacTime() - report.LastTimeStamp
									if timeDuration > report.Duration {
										report.Duration = timeDuration
										report.IndexPacketA = r.tFTimesLayer.index

										report.PacketA = report.Ring.Prev().Value.(*TFTimestampLayer)
										report.PacketB = &r.tFTimesLayer
									}
									report.LastTimeStamp = r.tFTimesLayer.IngressMacTime()
								} else {
									report.LastTimeStamp = r.tFTimesLayer.IngressMacTime()
									report.IndexPacketA = r.tFTimesLayer.index
								}

								report.Ring.Value = &r.tFTimesLayer
								report.Ring = report.Ring.Next()

							} else {
								fmt.Printf("Parse TFTimestamp layer failed, err: %v\n", e)
							}
						}
					}
				}
			}
		}
	}()

	return nil
}

func (r *PacketReceiver) Stop() {
	r.end <- struct{}{}
	time.Sleep(2 * time.Second)
	r.handle.Close()
	fmt.Printf("Packet Receiver stopped.\n")
}

func (r *PacketReceiver) Report() (str string) {
	if report.Rx != 0 {
		//str += fmt.Sprintln(t.PacketA.ToString())
		//str += fmt.Sprintln(t.PacketB.ToString())
		str += fmt.Sprintf("\rThe max gap happend between %d and %d... Max time duration: %.9f... Tx: %v... Rx: %v",
			report.IndexPacketA-1, report.IndexPacketA, report.Duration, report.Tx, report.Rx)
		//str += fmt.Sprintf("%-20s: %4.9f \n", "Max time duration", t.Duration)
		//str += fmt.Sprintf("%-20s: %d \n", "Tx", t.Tx)
		//str += fmt.Sprintf("%-20s: %d \n", "Rx", t.Rx)
	} else {
		str += "The report is empty"
	}
	return str
}
