package serve

import (
	"encoding/binary"
	"fmt"
	"io"
)

func readFrame(r io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(prefix[:])
	if size < headerSize {
		return nil, fmt.Errorf("invalid DNS TCP frame length %d", size)
	}
	message := make([]byte, int(size))
	if _, err := io.ReadFull(r, message); err != nil {
		return nil, err
	}
	return message, nil
}

func writeFrame(w io.Writer, frame []byte) error {
	if len(frame) < headerSize || len(frame) > maxWire {
		return fmt.Errorf("invalid DNS TCP frame length %d", len(frame))
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(frame)))
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, frame)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
