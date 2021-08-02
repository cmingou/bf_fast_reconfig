package main

import (
	"fmt"
	"github.com/P4Networking/bf_fast_reconfig/fastreconfig"
	"github.com/P4Networking/bf_fast_reconfig/pktgen"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type Config struct {
	hostAddr         string
	basePath         string
	p4Name           string
	profileName      string
	binaryPath       string
	contextPath      string
	bfRtPath         string
	receiveInterface string
	sendInterface    string
	emulator         bool
	packetSender     bool
	packetReceiver   bool
	allInOne         bool
}

var (
	cfg = new(Config)
	wg  sync.WaitGroup
)

func init() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Can not find config.yaml, err: %v\n", err)
		os.Exit(1)
	}

	cfg.hostAddr = viper.GetString("HostAddr")
	cfg.basePath = viper.GetString("BasePath")
	cfg.p4Name = viper.GetString("P4Name")
	cfg.profileName = viper.GetString("ProfileName")
	cfg.binaryPath = viper.GetString("BinaryPath")
	cfg.contextPath = viper.GetString("ContextPath")
	cfg.bfRtPath = viper.GetString("BfRtPath")
	cfg.receiveInterface = viper.GetString("ReceiveInterface")
	cfg.sendInterface = viper.GetString("SendInterface")
	cfg.emulator = viper.GetBool("Emulator")
	cfg.packetSender = viper.GetBool("PacketSender")
	cfg.packetReceiver = viper.GetBool("PacketReceiver")
	cfg.allInOne = viper.GetBool("AllInOne")

	if cfg.basePath[len(cfg.basePath)-1:] == "/" {
		cfg.basePath = cfg.basePath + "forwarding"
	} else {
		cfg.basePath = cfg.basePath + "/forwarding"
	}
}

func main() {
	pktSender := &pktgen.PacketSender{
		Port: cfg.sendInterface,
	}

	pktReceiver := &pktgen.PacketReceiver{
		Port: cfg.receiveInterface,
	}

	client := &fastreconfig.BfrtClient{
		ClientId:     0,
		DeviceId:     0,
		HostAddr:     cfg.hostAddr,
		BashPath:     cfg.basePath,
		P4Name:       cfg.p4Name,
		ProfileName:  cfg.profileName,
		BfrtJson:     cfg.bfRtPath,
		CtxJson:      cfg.contextPath,
		TofinoBinary: cfg.binaryPath,
	}

	if cfg.allInOne {
		// Start receive packet
		if err := pktReceiver.Start(); err != nil {
			fmt.Printf("Got error while start receive packet, err: %v", err)
		}

		// Start send packet
		if err := pktSender.Start(); err != nil {
			fmt.Printf("Got error while start send packet, err: %v", err)
		}

		// Start do fast reconfig
		if err := client.Reconfig(); err != nil {
			fmt.Printf("Failed to do fast reconfig, err: %v", err)
		}

		// Stop send packet
		pktSender.Stop()

		// Stop receive packet
		pktReceiver.Stop()

		// Print report
		fmt.Printf("Test report:\n%v\n", pktReceiver.Report())
	} else {

		if cfg.packetSender && cfg.packetReceiver {
			fmt.Printf("Can only choose be one of Sender or Receiver when All-in-one mode is not enable.\n")
			return
		}

		// as Packet receiver
		if cfg.packetReceiver && !cfg.packetSender {
			fmt.Printf("In packet receiver mode.\n")
			wg.Add(1)
			// Start receive packet
			if err := pktReceiver.Start(); err != nil {
				fmt.Printf("Got error while start receive packet, err: %v", err)
			}

			c := make(chan os.Signal)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-c
				fmt.Println("\n- Ctrl+C pressed in Terminal\n")
				pktReceiver.Stop()
				fmt.Printf("%v\n", pktReceiver.Report())
				wg.Done()
			}()

			wg.Wait()
		}

		// as Packet sender
		if cfg.packetSender && !cfg.packetReceiver {
			fmt.Printf("In packet sender mode.\n")

			// Start send packet
			if err := pktSender.Start(); err != nil {
				fmt.Printf("Got error while start send packet, err: %v", err)
			}

			// Start do fast reconfig
			if err := client.Reconfig(); err != nil {
				fmt.Printf("Failed to do fast reconfig, err: %v", err)
			}

			// Stop send packet
			pktSender.Stop()

			fmt.Printf("Complete did fast reconfig\n")
		}
	}
}
