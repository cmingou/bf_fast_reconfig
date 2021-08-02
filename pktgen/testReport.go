package pktgen

import (
	"container/ring"
	"fmt"
)

type TestReport struct {
	Duration      float64
	IndexPacketA  uint64
	IndexPacketB  uint64
	LastTimeStamp float64

	Tx uint64
	Rx uint64

	// The max time duration is between PacketA and PacketB
	PacketA *TFTimestampLayer
	PacketB *TFTimestampLayer

	Ring *ring.Ring
}

func (t *TestReport) ToString() (str string) {
	if t.Rx != 0 {
		//str += fmt.Sprintln(t.PacketA.ToString())
		//str += fmt.Sprintln(t.PacketB.ToString())
		str += fmt.Sprintf("\rThe max gap happend between %d and %d... Max time duration: %.9fs... Tx: %v... Rx: %v",
			t.IndexPacketA-1, t.IndexPacketA, t.Duration, t.Tx, t.Rx)
		//str += fmt.Sprintf("%-20s: %4.9f \n", "Max time duration", t.Duration)
		//str += fmt.Sprintf("%-20s: %d \n", "Tx", t.Tx)
		//str += fmt.Sprintf("%-20s: %d \n", "Rx", t.Rx)
	}
	return str
}
