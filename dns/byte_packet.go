package dns

import (
	"errors"
	"fmt"
	"strings"
)

type BytePacketBuffer struct {
	Buf [512]byte
	Pos uint16
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{}
}

func (b *BytePacketBuffer) SetBuffer(buf []byte) {
	copy(b.Buf[:], buf)
}

func (b *BytePacketBuffer) Set(pos uint16, val byte) {
	b.Buf[pos] = val
}

func (b *BytePacketBuffer) Set2Bytes(pos uint16, val uint16) {
	b.Set(pos, byte(val>>8))
	b.Set(pos+1, byte(val&0xFF))
}

func (b *BytePacketBuffer) Step(steps uint16) error {
	b.Pos += steps
	return nil
}

func (b *BytePacketBuffer) Seek(pos uint16) error {
	b.Pos = pos
	return nil
}

func (b *BytePacketBuffer) Read() (byte, error) {
	if b.Pos >= 512 {
		return 0, errors.New("end of buffer")
	}

	r := b.Buf[b.Pos]
	b.Pos += 1
	return r, nil
}

func (b *BytePacketBuffer) Get(pos uint16) (byte, error) {
	if pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	return b.Buf[pos], nil
}

func (b *BytePacketBuffer) GetRange(start, len uint16) ([]byte, error) {
	if start+len >= 512 {
		return nil, errors.New("end of buffer")
	}

	return b.Buf[start : start+len], nil
}

func (b *BytePacketBuffer) Read2Bytes() (uint16, error) {
	byte1, err := b.Read()
	if err != nil {
		return 0, err
	}
	byte2, err := b.Read()
	if err != nil {
		return 0, err
	}
	return (uint16(byte1) << 8) | uint16(byte2), nil
}

func (b *BytePacketBuffer) Read4Bytes() (uint32, error) {
	byte1, err := b.Read()
	if err != nil {
		return 0, err
	}
	byte2, err := b.Read()
	if err != nil {
		return 0, err
	}
	byte3, err := b.Read()
	if err != nil {
		return 0, err
	}
	byte4, err := b.Read()
	if err != nil {
		return 0, err
	}
	return uint32(byte1)<<24 | uint32(byte2)<<16 | uint32(byte3)<<8 | uint32(byte4), nil
}

// ReadQName reads a q name
//
//	The tricky part: Reading domain names, taking labels into consideration.
//	Will take something like [3]www[6]google[3]com[0] and append
//	www.google.com.
func (b *BytePacketBuffer) ReadQName() (string, error) {
	var sb strings.Builder
	pos := b.Pos

	jumped := false
	maxJums := 5
	jumpsPerformed := 0

	delim := ""

	for {
		if jumpsPerformed > maxJums {
			return "", fmt.Errorf("limit of %d jums exceeded", maxJums)
		}

		lenByte, err := b.Get(pos)
		if err != nil {
			return "", err
		}

		// If len has the two most significant bit are set, it represents a
		// jump to some other offset in the packet:
		if (lenByte & 0xC0) == 0xC0 {
			if !jumped {
				if err := b.Seek(pos + 2); err != nil {
					return "", err
				}
			}

			b2, err := b.Get(pos + 1)
			if err != nil {
				return "", err
			}

			offset := (((uint16(lenByte) ^ 0xC0) << 8) | uint16(b2))
			pos = offset

			jumped = true
			jumpsPerformed++
			continue
		} else {
			pos += 1

			// Domain names are terminated by an empty label of length 0,
			// so if the length is zero we're done.
			if lenByte == 0 {
				break
			}

			sb.WriteString(delim)

			bs, err := b.GetRange(pos, uint16(lenByte))
			if err != nil {
				return "", err
			}

			sb.WriteString(strings.ToLower(string(bs)))

			delim = "."

			pos += uint16(lenByte)
		}
	}

	if !jumped {
		if err := b.Seek(pos); err != nil {
			return "", err
		}
	}

	return sb.String(), nil
}

func (b *BytePacketBuffer) write(val byte) error {
	if b.Pos >= 512 {
		return errors.New("end of buffer")
	}
	b.Buf[b.Pos] = val
	b.Pos += 1
	return nil
}

func (b *BytePacketBuffer) Write1Byte(val uint8) error {
	return b.write(val)
}

func (b *BytePacketBuffer) Write2Byte(val uint16) error {
	err := b.write(uint8(val >> 8))
	if err != nil {
		return err
	}
	return b.write(uint8(val & 0xFF))
}

func (b *BytePacketBuffer) Write4Byte(val uint32) error {
	err := b.write(uint8((val >> 24) & 0xFF))
	if err != nil {
		return err
	}

	err = b.write(uint8((val >> 16) & 0xFF))
	if err != nil {
		return err
	}

	err = b.write(uint8((val >> 8) & 0xFF))
	if err != nil {
		return err
	}
	return b.write(uint8(val & 0xFF))
}

func (b *BytePacketBuffer) WriteQName(qname string) error {
	var err error
	for _, label := range strings.Split(qname, ".") {
		n := len(label)
		if n > 0x3f {
			return errors.New("signle label exceeds 63 characters of length")
		}

		err = b.Write1Byte(byte(n))
		if err != nil {
			return err
		}

		for _, b1 := range []byte(label) {
			err = b.Write1Byte(b1)
			if err != nil {
				return err
			}
		}

		err = b.Write1Byte(byte(0))
		if err != nil {
			return err
		}
	}
	return nil
}
