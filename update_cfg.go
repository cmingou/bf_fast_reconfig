package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/P4Networking/proto/go/p4"
	"google.golang.org/grpc"
	"log"
	"os"
)

type bfrtClient struct {
	client   p4.BfRuntimeClient
	stream   p4.BfRuntime_StreamChannelClient
	host     string
	clientId uint32
	deviceId uint32
	p4Name   string
}

var (
	hostAddr    string
	tofinoBin   string
	ctxJson     string
	p4Name      string
	profileName string
	bfrtJson    string
	bashPath    string
)

func init() {
	flag.StringVar(&p4Name, "p4-name", "", "p4 program `name`")
	flag.StringVar(&profileName, "profile-name", "", "profile `name`")
	flag.StringVar(&hostAddr, "addr", ":50052", "bfrt server `addr`")
	flag.StringVar(&tofinoBin, "bin", "", "Location of `Tofino.bin` output from p4c")
	flag.StringVar(&bfrtJson, "bfrt", "", "Location of `bf-rt.json`")
	flag.StringVar(&ctxJson, "ctx", "", "Location of Tofino `conext.json` output from p4c")
	flag.StringVar(&bashPath, "base", "", "Bash path")
	flag.Parse()
}

func readWrite(fileName string) []byte {

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		log.Fatal(statsErr)
	}

	byteArray := make([]byte, stats.Size())

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(byteArray)

	return byteArray
}

func main() {
	bfrtClient := &bfrtClient{
		host:     hostAddr,
		clientId: 0,
		deviceId: 0,
		p4Name:   p4Name,
	}

	conn, err := grpc.Dial(bfrtClient.host, grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128*1024*1024),
			grpc.MaxCallSendMsgSize(128*1024*1024)))
	if err != nil {
		log.Fatal(err)
	}

	bfrtClient.client = p4.NewBfRuntimeClient(conn)

	bfrtClient.stream, err = bfrtClient.client.StreamChannel(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	mastershipReq := &p4.StreamMessageRequest{
		Update: &p4.StreamMessageRequest_Subscribe{
			Subscribe: &p4.Subscribe{
				DeviceId: bfrtClient.deviceId,
				IsMaster: true,
				Notifications: &p4.Subscribe_Notifications{
					EnableLearnNotifications:            true,
					EnableIdletimeoutNotifications:      true,
					EnablePortStatusChangeNotifications: true,
				},
			},
		},
	}

	err = bfrtClient.stream.Send(mastershipReq)

	var req *p4.SetForwardingPipelineConfigRequest
	var rsp *p4.SetForwardingPipelineConfigResponse

	req = &p4.SetForwardingPipelineConfigRequest{
		ClientId:    bfrtClient.clientId,
		DeviceId:    bfrtClient.deviceId,
		Action:      p4.SetForwardingPipelineConfigRequest_VERIFY_AND_WARM_INIT_BEGIN_AND_END,
		BasePath:    bashPath,
		DevInitMode: p4.SetForwardingPipelineConfigRequest_FAST_RECONFIG,
		Config: []*p4.ForwardingPipelineConfig{
			{
				P4Name:        bfrtClient.p4Name,
				BfruntimeInfo: readWrite(bfrtJson),
				Profiles: []*p4.ForwardingPipelineConfig_Profile{
					&p4.ForwardingPipelineConfig_Profile{
						ProfileName: profileName,
						Context:     readWrite(ctxJson),
						Binary:      readWrite(tofinoBin),
						PipeScope:   []uint32{0,1,2,3},
					},
				},
			},
		},
	}
	fmt.Printf("\n\nP4 Name: %s, \nbash path: %s, \nbfrt path: %v, \nprofile Name: %v, \ncontext: %v, \nbin: %v\n\n",
		bfrtClient.p4Name, bashPath, bfrtJson, profileName, ctxJson, tofinoBin)

	rsp, err = bfrtClient.client.SetForwardingPipelineConfig(context.Background(), req)
	if err != nil {
		fmt.Printf("%-30s: %v\n", "REQ_VERIFY_AND_WARM_INIT_BEGIN_AND_END_FAILED", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%-30s: %v\n", "REQ_VERIFY_AND_WARM_INIT_BEGIN_AND_END", rsp.String())

	//req = &p4.SetForwardingPipelineConfigRequest{
	//	ClientId: bfrtClient.clientId,
	//	DeviceId: bfrtClient.deviceId,
	//	Action:   p4.SetForwardingPipelineConfigRequest_BIND,
	//	Config: []*p4.ForwardingPipelineConfig{
	//		{
	//			P4Name: bfrtClient.p4Name,
	//			Profiles: []*p4.ForwardingPipelineConfig_Profile{
	//				&p4.ForwardingPipelineConfig_Profile{
	//					ProfileName: bfrtClient.p4Name,
	//					Context:     readWrite(ctxJson),
	//					Binary:      readWrite(tofinoBin),
	//					PipeScope:   []uint32{0, 1, 2, 3},
	//				},
	//			},
	//		},
	//	},
	//}
	//rsp, err = bfrtClient.client.SetForwardingPipelineConfig(context.Background(), req)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Printf("%-30s: %v\n", "REQ_BIND", rsp.String())
	//
}
