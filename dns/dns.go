package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type ResultCode int
type RecordType int

const (
	NOERROR ResultCode = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

const (
	UNKNOWN RecordType = iota
	A
	NS
	CNAME
	MX
	AAAA
)

type DnsHeader struct {
	ID                   uint16     // 16 bits
	RecursionDesired     bool       // 1 bit
	TruncatedMessage     bool       // 1 bit
	AuthoritativeAnswer  bool       // 1 bit
	Opcode               uint8      // 4 bits
	Response             bool       // 1 bit
	Rescode              ResultCode // 4 bits
	CheckingDisabled     bool       // 1 bit
	AuthedData           bool       // 1 bit
	Z                    bool       // 1 bit
	RecursionAvailable   bool       // 1 bit
	Questions            uint16     // 16 bits
	Answers              uint16     // 16 bits
	AuthoritativeEntries uint16     // 16 bits
	ResourceEntries      uint16     // 16 bits
}

func NewDnsHeader() *DnsHeader {
	return &DnsHeader{
		Rescode: NOERROR,
	}
}

func (h *DnsHeader) Write(buffer *BytePacketBuffer) error {
	err := buffer.Write2Byte(h.ID)
	if err != nil {
		return err
	}

	flag := uint8(0)
	if h.RecursionDesired {
		flag |= 1
	}

	if h.TruncatedMessage {
		flag |= (1 << 1)
	}

	if h.AuthoritativeAnswer {
		flag |= (1 << 2)
	}

	flag |= (h.Opcode << 3)

	if h.Response {
		flag |= (1 << 7)
	}

	err = buffer.Write1Byte(flag)
	if err != nil {
		return err
	}

	flag = uint8(0)
	flag |= uint8(h.Rescode)

	if h.CheckingDisabled {
		flag |= (1 << 4)
	}

	if h.AuthedData {
		flag |= (1 << 5)
	}

	if h.Z {
		flag |= (1 << 6)
	}

	if h.RecursionAvailable {
		flag |= (1 << 7)
	}

	err = buffer.Write2Byte(h.Questions)
	if err != nil {
		return err
	}

	err = buffer.Write2Byte(h.Answers)
	if err != nil {
		return err
	}

	err = buffer.Write2Byte(h.AuthoritativeEntries)
	if err != nil {
		return err
	}
	return buffer.Write2Byte(h.ResourceEntries)
}

// Read parses a BytePacketBuffer and populates the DnsHeader fields
func (h *DnsHeader) Read(buffer *BytePacketBuffer) error {
	var err error

	h.ID, err = buffer.Read2Bytes()
	if err != nil {
		return err
	}

	flags, err := buffer.Read2Bytes()
	if err != nil {
		return err
	}

	a := uint8(flags >> 8)
	b := uint8(flags & 0xFF)

	// 1 0 0 0 0 0 0 1  1 0 0 0 0 0 0 0
	// - -+-+-+- - - -  - -+-+- -+-+-+-
	// Q    O    A T R  R   Z      R
	// R    P    A C D  A          C
	//      C                      O
	//      O                      D
	//      D                      E
	//      E

	h.RecursionDesired = (a & (1 << 0)) > 0
	h.TruncatedMessage = (a & (1 << 1)) > 0
	h.AuthoritativeAnswer = (a & (1 << 2)) > 0
	h.Opcode = (a >> 3) & 0x0F
	h.Response = (a & (1 << 7)) > 0

	h.Rescode = FromNum2ResultCode(b & 0x0F)
	h.CheckingDisabled = (b & (1 << 4)) > 0
	h.AuthedData = (b & (1 << 5)) > 0
	h.Z = (b & (1 << 6)) > 0
	h.RecursionAvailable = (b & (1 << 7)) > 0

	h.Questions, err = buffer.Read2Bytes()
	if err != nil {
		return err
	}

	h.Answers, err = buffer.Read2Bytes()
	if err != nil {
		return err
	}

	h.AuthoritativeEntries, err = buffer.Read2Bytes()
	if err != nil {
		return err
	}

	h.ResourceEntries, err = buffer.Read2Bytes()
	if err != nil {
		return err
	}
	return nil
}

type DnsPacket struct {
	Header      *DnsHeader
	Questions   []*DnsQuestion
	Answers     []*DnsRecord
	Authorities []*DnsRecord
	Resources   []*DnsRecord
}

func NewDnsPacket() *DnsPacket {
	return &DnsPacket{
		Header:      &DnsHeader{},
		Questions:   []*DnsQuestion{},
		Answers:     []*DnsRecord{},
		Authorities: []*DnsRecord{},
		Resources:   []*DnsRecord{},
	}
}

func (d *DnsPacket) Write(buffer *BytePacketBuffer) error {
	d.Header.Questions = uint16(len(d.Questions))
	d.Header.Answers = uint16(len(d.Answers))
	d.Header.AuthoritativeEntries = uint16(len(d.Authorities))
	d.Header.ResourceEntries = uint16(len(d.Resources))

	err := d.Header.Write(buffer)
	if err != nil {
		return err
	}

	for _, q := range d.Questions {
		err = q.Write(buffer)
		if err != nil {
			return err
		}
	}

	for _, a := range d.Answers {
		_, err = a.Write(buffer)
		if err != nil {
			return err
		}
	}

	for _, a := range d.Authorities {
		_, err = a.Write(buffer)
		if err != nil {
			return err
		}
	}

	for _, r := range d.Resources {
		_, err = r.Write(buffer)
		if err != nil {
			return err
		}
	}

	return nil
}

func FromBuffer2DnsPacket(buffer *BytePacketBuffer) (*DnsPacket, error) {
	packet := NewDnsPacket()
	if err := packet.Header.Read(buffer); err != nil {
		return nil, err
	}

	for i := 0; i < int(packet.Header.Questions); i++ {

		q := NewDnsQuestion("", UNKNOWN)
		err := q.Read(buffer)
		if err != nil {
			return nil, err
		}

		packet.Questions = append(packet.Questions, q)
	}

	for i := 0; i < int(packet.Header.Answers); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Answers = append(packet.Answers, record)
	}

	for i := 0; i < int(packet.Header.AuthoritativeEntries); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Authorities = append(packet.Authorities, record)
	}

	for i := 0; i < int(packet.Header.ResourceEntries); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Resources = append(packet.Resources, record)
	}

	return packet, nil
}

func FromNum2ResultCode(num uint8) ResultCode {
	switch num {
	case 1:
		return FORMERR
	case 2:
		return SERVFAIL
	case 3:
		return NXDOMAIN
	case 4:
		return NOTIMP
	case 5:
		return REFUSED
	default:
		return NOERROR
	}
}

func RecordTypeToNum(typ RecordType) uint16 {
	switch typ {
	case A:
		return 1
	case NS:
		return 2
	case CNAME:
		return 5
	case MX:
		return 15
	case AAAA:
		return 28
	default:
		return 0
	}
}

func FromNum2RecordType(num uint16) RecordType {
	switch num {
	case 1:
		return A
	case 2:
		return NS
	case 5:
		return CNAME
	case 15:
		return MX
	case 28:
		return AAAA
	default:
		return UNKNOWN
	}
}

type DnsQuestion struct {
	Name string
	Type RecordType
}

func NewDnsQuestion(name string, qtype RecordType) *DnsQuestion {
	return &DnsQuestion{
		Name: name,
		Type: qtype,
	}
}

func (dq *DnsQuestion) Write(buffer *BytePacketBuffer) error {
	err := buffer.WriteQName(dq.Name)
	if err != nil {
		return err

	}

	err = buffer.Write2Byte(uint16(dq.Type))
	if err != nil {
		return err
	}

	return buffer.Write2Byte(uint16(1))
}

func (dq *DnsQuestion) Read(buffer *BytePacketBuffer) error {
	var err error

	dq.Name, err = buffer.ReadQName()
	if err != nil {
		return err
	}

	qtype, err := buffer.Read2Bytes()
	if err != nil {
		return err
	}

	dq.Type = FromNum2RecordType(qtype)

	_, err = buffer.Read2Bytes() // class
	return err
}

type DnsRecord struct {
	Type     RecordType
	Domain   string
	QType    uint16 // Used for UNKNOWN
	DataLen  uint16 // Used for UNKNOWN
	TTL      uint32
	Addr     net.IP // Used for A/AAAA
	Host     string // NS/CNAME
	Priority uint16 // MX

}

func NewUnknownDnsRecord(domain string, qtype, dataLen uint16, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:    UNKNOWN,
		Domain:  domain,
		QType:   qtype,
		DataLen: dataLen,
		TTL:     ttl,
	}
}

func NewADnsRecord(domain string, addr net.IP, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:   A,
		Domain: domain,
		Addr:   addr,
		TTL:    ttl,
	}
}

func NewNSDnsRecord(domain, host string, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:   NS,
		Domain: domain,
		Host:   host,
		TTL:    ttl,
	}
}

func NewCNameDnsRecord(domain, host string, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:   CNAME,
		Domain: domain,
		Host:   host,
		TTL:    ttl,
	}
}

func NewMXDnsRecord(domain, host string, priority uint16, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:     MX,
		Domain:   domain,
		Host:     host,
		Priority: priority,
		TTL:      ttl,
	}
}

func NewAAAADnsRecord(domain string, addr net.IP, ttl uint32) *DnsRecord {
	return &DnsRecord{
		Type:   AAAA,
		Domain: domain,
		Addr:   addr,
		TTL:    ttl,
	}
}

func ReadDnsRecord(buffer *BytePacketBuffer) (*DnsRecord, error) {
	domain, err := buffer.ReadQName()
	if err != nil {
		return nil, err
	}

	qtypeNum, err := buffer.Read2Bytes()
	if err != nil {
		return nil, err
	}

	qtype := FromNum2RecordType(qtypeNum)

	if _, err := buffer.Read2Bytes(); err != nil { // class
		return nil, err
	}

	ttl, err := buffer.Read4Bytes()
	if err != nil {
		return nil, err
	}

	dataLen, err := buffer.Read2Bytes()
	if err != nil {
		return nil, err
	}

	switch qtype {
	case A:
		rawAddr, err := buffer.Read4Bytes()
		if err != nil {
			return nil, err
		}

		addr := net.IPv4(
			byte((rawAddr>>24)&0xFF),
			byte((rawAddr>>16)&0xFF),
			byte((rawAddr>>8)&0xFF),
			byte((rawAddr)&0xFF),
		)

		return NewADnsRecord(domain, addr, ttl), nil

	case AAAA:
		raw_addr1, err := buffer.Read4Bytes()
		if err != nil {
			return nil, err
		}
		raw_addr2, err := buffer.Read4Bytes()
		if err != nil {
			return nil, err
		}
		raw_addr3, err := buffer.Read4Bytes()
		if err != nil {
			return nil, err
		}
		raw_addr4, err := buffer.Read4Bytes()
		if err != nil {
			return nil, err
		}
		addr := net.IP{
			byte((raw_addr1 >> 24) & 0xFF),
			byte((raw_addr1 >> 16) & 0xFF),
			byte((raw_addr1 >> 8) & 0xFF),
			byte((raw_addr1 >> 0) & 0xFF),
			byte((raw_addr2 >> 24) & 0xFF),
			byte((raw_addr2 >> 16) & 0xFF),
			byte((raw_addr2 >> 8) & 0xFF),
			byte((raw_addr2 >> 0) & 0xFF),
			byte((raw_addr3 >> 24) & 0xFF),
			byte((raw_addr3 >> 16) & 0xFF),
			byte((raw_addr3 >> 8) & 0xFF),
			byte((raw_addr3 >> 0) & 0xFF),
			byte((raw_addr4 >> 24) & 0xFF),
			byte((raw_addr4 >> 16) & 0xFF),
			byte((raw_addr4 >> 8) & 0xFF),
			byte((raw_addr4 >> 0) & 0xFF),
		}

		return NewAAAADnsRecord(domain, addr, ttl), nil
	case NS:
		ns, err := buffer.ReadQName()
		if err != nil {
			return nil, err
		}
		return NewNSDnsRecord(domain, ns, ttl), nil
	case CNAME:
		cname, err := buffer.ReadQName()
		if err != nil {
			return nil, err
		}
		return NewCNameDnsRecord(domain, cname, ttl), nil
	case MX:
		priority, err := buffer.Read2Bytes()
		if err != nil {
			return nil, err
		}
		mx, err := buffer.ReadQName()
		if err != nil {
			return nil, err
		}
		return NewMXDnsRecord(domain, mx, priority, ttl), nil
	default:
		if err := buffer.Step(uint16(dataLen)); err != nil {
			return nil, err
		}

		return &DnsRecord{
			Type:    UNKNOWN,
			Domain:  domain,
			QType:   qtypeNum,
			DataLen: dataLen,
			TTL:     ttl,
		}, nil
	}
}

func (d *DnsRecord) Write(buffer *BytePacketBuffer) (uint16, error) {
	startPos := buffer.Pos

	switch d.Type {
	case A:
		err := buffer.WriteQName(d.Domain)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(RecordTypeToNum(A)))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(1))
		if err != nil {
			return 0, err
		}
		err = buffer.Write4Byte(d.TTL)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(4))
		if err != nil {
			return 0, err
		}

		ip := d.Addr.To4()
		if ip == nil {
			return 0, errors.New("invalid IPv4 address")
		}

		err = buffer.Write1Byte(ip[0])
		if err != nil {
			return 0, err
		}
		err = buffer.Write1Byte(ip[1])
		if err != nil {
			return 0, err
		}
		err = buffer.Write1Byte(ip[2])
		if err != nil {
			return 0, err
		}
		err = buffer.Write1Byte(ip[3])
		if err != nil {
			return 0, err
		}
	case NS:
		err := buffer.WriteQName(d.Domain)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(RecordTypeToNum(NS)))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(1))
		if err != nil {
			return 0, err
		}
		err = buffer.Write4Byte(d.TTL)
		if err != nil {
			return 0, err
		}
		pos := buffer.Pos
		err = buffer.Write2Byte(uint16(0))
		if err != nil {
			return 0, err
		}
		err = buffer.WriteQName(d.Host)
		if err != nil {
			return 0, err
		}

		size := buffer.Pos - (pos + 2)
		buffer.Set2Bytes(pos, size)
	case CNAME:
		err := buffer.WriteQName(d.Domain)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(RecordTypeToNum(CNAME)))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(1))
		if err != nil {
			return 0, err
		}
		err = buffer.Write4Byte(d.TTL)
		if err != nil {
			return 0, err
		}
		pos := buffer.Pos
		err = buffer.Write2Byte(uint16(0))
		if err != nil {
			return 0, err
		}
		err = buffer.WriteQName(d.Host)
		if err != nil {
			return 0, err
		}

		size := buffer.Pos - (pos + 2)
		buffer.Set2Bytes(pos, size)
	case MX:
		err := buffer.WriteQName(d.Domain)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(RecordTypeToNum(MX)))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(1))
		if err != nil {
			return 0, err
		}
		err = buffer.Write4Byte(d.TTL)
		if err != nil {
			return 0, err
		}
		pos := buffer.Pos
		err = buffer.Write2Byte(uint16(0))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(d.Priority)
		if err != nil {
			return 0, err
		}
		err = buffer.WriteQName(d.Host)
		if err != nil {
			return 0, err
		}

		size := buffer.Pos - (pos + 2)
		buffer.Set2Bytes(pos, size)
	case AAAA:
		err := buffer.WriteQName(d.Domain)
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(RecordTypeToNum(AAAA)))
		if err != nil {
			return 0, err
		}
		err = buffer.Write2Byte(uint16(1))
		if err != nil {
			return 0, err
		}
		err = buffer.Write4Byte(d.TTL)
		if err != nil {
			return 0, err
		}
		pos := buffer.Pos
		err = buffer.Write2Byte(uint16(16))
		if err != nil {
			return 0, err
		}

		ip := d.Addr.To16()
		if ip == nil {
			return 0, fmt.Errorf("invalid IPv6 address")
		}

		for i := 0; i < len(ip); i += 2 {
			segment := binary.BigEndian.Uint16(ip[i : i+2])
			err = buffer.Write2Byte(segment)
			if err != nil {
				return 0, err
			}
		}

		size := buffer.Pos - (pos + 2)
		buffer.Set2Bytes(pos, size)
	case UNKNOWN:
		fmt.Printf("Skipping record: %v\n", d)
	}

	return (buffer.Pos - startPos), nil
}
