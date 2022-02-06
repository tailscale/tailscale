// +build gofuzz

package dhcpv4

import (
	"fmt"
	"reflect"
)

// Fuzz is the entrypoint for go-fuzz
func Fuzz(data []byte) int {
	msg, err := FromBytes(data)
	if err != nil {
		return 0
	}

	serialized := msg.ToBytes()

	// Compared to dhcpv6, dhcpv4 has padding and fixed-size fields containing
	// variable-length data; We can't expect the library to output byte-for-byte
	// identical packets after a round-trip.
	// Instead, we check that after a round-trip, the packet reserializes to the
	// same internal representation
	rtMsg, err := FromBytes(serialized)

	if err != nil || !reflect.DeepEqual(msg, rtMsg) {
		fmt.Printf("Input:      %x\n", data)
		fmt.Printf("Round-trip: %x\n", serialized)
		fmt.Println("Message: ", msg.Summary())
		fmt.Printf("Go repr: %#v\n", msg)
		fmt.Println("Reserialized: ", rtMsg.Summary())
		fmt.Printf("Go repr: %#v\n", rtMsg)
		if err != nil {
			fmt.Printf("Got error while reserializing: %v\n", err)
			panic("round-trip error: " + err.Error())
		}
		panic("round-trip different: " + msg.Summary())
	}

	return 1
}
