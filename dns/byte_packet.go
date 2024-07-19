package dns

import (
	"errors"
	"fmt"
	"strings"
)

type BytePacketBuffer struct {
	buf [512]byte
	pos uint16
}

func NewBytePacketBuffer() *BytePacketBuffer {
	return &BytePacketBuffer{}
}

func (b *BytePacketBuffer) SetBuffer(buf []byte) {
	copy(b.buf[:], buf)
}

func (b *BytePacketBuffer) Pos() uint16 {
	return b.pos
}

func (b *BytePacketBuffer) Step(steps uint16) error {
	b.pos += steps
	return nil
}

func (b *BytePacketBuffer) Seek(pos uint16) error {
	b.pos = pos
	return nil
}

func (b *BytePacketBuffer) Read() (byte, error) {
	if b.pos >= 512 {
		return 0, errors.New("end of buffer")
	}

	r := b.buf[b.pos]
	b.pos += 1
	return r, nil
}

func (b *BytePacketBuffer) Get(pos uint16) (byte, error) {
	if pos >= 512 {
		return 0, errors.New("end of buffer")
	}
	return b.buf[pos], nil
}

func (b *BytePacketBuffer) GetRange(start, len uint16) ([]byte, error) {
	if start+len >= 512 {
		return nil, errors.New("end of buffer")
	}

	return b.buf[start : start+len], nil
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
	pos := b.pos

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
