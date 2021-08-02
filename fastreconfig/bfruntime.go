package fastreconfig

import (
	"bufio"
	"context"
	"github.com/P4Networking/proto/go/p4"
	"google.golang.org/grpc"
	"log"
	"os"
)

type BfrtClient struct {
	client   p4.BfRuntimeClient
	stream   p4.BfRuntime_StreamChannelClient
	HostAddr string
	ClientId uint32
	DeviceId uint32

	BashPath     string
	P4Name       string
	ProfileName  string
	BfrtJson     string
	TofinoBinary string
	CtxJson      string
}

func (c *BfrtClient) Reconfig() error {
	conn, err := grpc.Dial(c.HostAddr, grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128*1024*1024),
			grpc.MaxCallSendMsgSize(128*1024*1024)))
	if err != nil {
		return err
	}

	c.client = p4.NewBfRuntimeClient(conn)

	c.stream, err = c.client.StreamChannel(context.Background())
	if err != nil {
		return err
	}

	mastershipReq := &p4.StreamMessageRequest{
		Update: &p4.StreamMessageRequest_Subscribe{
			Subscribe: &p4.Subscribe{
				DeviceId: c.DeviceId,
				IsMaster: true,
				Notifications: &p4.Subscribe_Notifications{
					EnableLearnNotifications:            true,
					EnableIdletimeoutNotifications:      true,
					EnablePortStatusChangeNotifications: true,
				},
			},
		},
	}

	err = c.stream.Send(mastershipReq)

	var (
		req *p4.SetForwardingPipelineConfigRequest
	)

	req = &p4.SetForwardingPipelineConfigRequest{
		ClientId:    c.ClientId,
		DeviceId:    c.DeviceId,
		Action:      p4.SetForwardingPipelineConfigRequest_VERIFY_AND_WARM_INIT_BEGIN_AND_END,
		BasePath:    c.BashPath,
		DevInitMode: p4.SetForwardingPipelineConfigRequest_FAST_RECONFIG,
		Config: []*p4.ForwardingPipelineConfig{
			{
				P4Name:        c.P4Name,
				BfruntimeInfo: readFile(c.BfrtJson),
				Profiles: []*p4.ForwardingPipelineConfig_Profile{
					&p4.ForwardingPipelineConfig_Profile{
						ProfileName: c.ProfileName,
						Context:     readFile(c.CtxJson),
						Binary:      readFile(c.TofinoBinary),
						PipeScope:   []uint32{0, 1, 2, 3},
					},
				},
			},
		},
	}

	if _, err := c.client.SetForwardingPipelineConfig(context.Background(), req); err != nil {
		return err
	}
	return nil
}

func readFile(fileName string) []byte {
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
