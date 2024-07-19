package main

import (
	"fmt"
	"os"

	"github.com/Ysoding/go-dns/dns"
)

func main() {
	data, err := os.ReadFile("google_response_packet.txt")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	buffer := dns.NewBytePacketBuffer()
	buffer.SetBuffer(data)

	packet, err := dns.FromBuffer2DnsPacket(buffer)
	if err != nil {
		fmt.Println("Error parsing packet:", err)
		return
	}

	fmt.Printf("Header: %+v\n", packet.Header)
	for _, q := range packet.Questions {
		fmt.Printf("Question: %+v\n", q)
	}
	for _, rec := range packet.Answers {
		fmt.Printf("Answer: %+v\n", rec)
	}
	for _, rec := range packet.Authorities {
		fmt.Printf("Authority: %+v\n", rec)
	}
	for _, rec := range packet.Resources {
		fmt.Printf("Resource: %+v\n", rec)
	}
}
