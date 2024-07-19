package dns

import "net"

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

type DnsQuestion struct {
	Name  string
	QType RecordType
}

type DnsRecord struct {
	Type    RecordType
	Domain  string
	QType   uint16 // Used for UNKNOWN
	DataLen uint16 // Used for UNKNOWN
	TTL     uint32
	Addr    net.IP // Used for A
}

type DnsPacket struct {
	Header      DnsHeader
	Questions   []DnsQuestion
	Answers     []DnsRecord
	Authorities []DnsRecord
	Resources   []DnsRecord
}

func NewDnsPacket() *DnsPacket {
	return &DnsPacket{
		Header:      DnsHeader{},
		Questions:   []DnsQuestion{},
		Answers:     []DnsRecord{},
		Authorities: []DnsRecord{},
		Resources:   []DnsRecord{},
	}
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

		packet.Questions = append(packet.Questions, *q)
	}

	for i := 0; i < int(packet.Header.Answers); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Answers = append(packet.Answers, *record)
	}

	for i := 0; i < int(packet.Header.AuthoritativeEntries); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Authorities = append(packet.Authorities, *record)
	}

	for i := 0; i < int(packet.Header.ResourceEntries); i++ {
		record, err := ReadDnsRecord(buffer)
		if err != nil {
			return nil, err
		}
		packet.Resources = append(packet.Resources, *record)
	}

	return packet, nil
}

func NewDnsHeader() *DnsHeader {
	return &DnsHeader{
		Rescode: NOERROR,
	}
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

func FromNum2RecordType(num uint16) RecordType {
	switch num {
	case 1:
		return A
	default:
		return UNKNOWN
	}
}

func NewDnsQuestion(name string, qtype RecordType) *DnsQuestion {
	return &DnsQuestion{
		Name:  name,
		QType: qtype,
	}
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

	dq.QType = FromNum2RecordType(qtype)

	_, err = buffer.Read2Bytes() // class
	return err
}

func NewUnknownDnsRecord(domain string, qtype, dataLen uint16, ttl uint32) DnsRecord {
	return DnsRecord{
		Type:    UNKNOWN,
		Domain:  domain,
		QType:   qtype,
		DataLen: dataLen,
		TTL:     ttl,
	}
}

func NewADnsRecord(domain string, addr net.IP, ttl uint32) DnsRecord {
	return DnsRecord{
		Type:   A,
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
			byte(rawAddr>>24),
			byte(rawAddr>>16),
			byte(rawAddr>>8),
			byte(rawAddr),
		)

		return &DnsRecord{
			Type:   A,
			Domain: domain,
			TTL:    ttl,
			Addr:   addr,
		}, nil

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
