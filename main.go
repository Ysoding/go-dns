package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Ysoding/go-dns/dns"
)

func main() {
	qname := "google.com"
	// qname := "www.yahoo.com"
	qtype := dns.A

	server := "8.8.8.8:53"

	socket, err := net.ListenPacket("udp", "0.0.0.0:9999")
	if err != nil {
		fmt.Println("Error binding UDP socket:", err)
		os.Exit(1)
	}
	defer socket.Close()

	packet := dns.NewDnsPacket()
	packet.Header.ID = 6666
	packet.Header.Questions = 1
	packet.Header.RecursionDesired = true
	packet.Questions = append(packet.Questions, dns.NewDnsQuestion(qname, qtype))

	reqBuffer := dns.NewBytePacketBuffer()
	err = packet.Write(reqBuffer)
	if err != nil {
		fmt.Println("Error writing DNS packet:", err)
		os.Exit(1)
	}

	// Send the packet to the server
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		fmt.Println("Error resolving server address:", err)
		os.Exit(1)
	}

	_, err = socket.WriteTo(reqBuffer.Buf[:reqBuffer.Pos], serverAddr)
	if err != nil {
		fmt.Println("Error sending DNS packet:", err)
		os.Exit(1)
	}

	respBuffer := dns.NewBytePacketBuffer()
	socket.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, _, err = socket.ReadFrom(respBuffer.Buf[:])
	if err != nil {
		fmt.Println("Error receiving DNS response:", err)
		os.Exit(1)
	}

	resPacket, err := dns.FromBuffer2DnsPacket(respBuffer)
	if err != nil {
		fmt.Println("Error parsing DNS response:", err)
		os.Exit(1)
	}

	fmt.Printf("%#v\n", resPacket.Header)

	for _, q := range resPacket.Questions {
		fmt.Printf("%#v\n", q)
	}
	for _, rec := range resPacket.Answers {
		fmt.Printf("%#v\n", rec)
	}
	for _, rec := range resPacket.Authorities {
		fmt.Printf("%#v\n", rec)
	}
	for _, rec := range resPacket.Resources {
		fmt.Printf("%#v\n", rec)
	}
}
