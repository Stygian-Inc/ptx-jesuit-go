package ptxloader

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/Stygian-Inc/ptx-jesuit-go/ptx"
	"google.golang.org/protobuf/proto"
)

var MagicHeader = []byte{0x50, 0x54, 0x58, 0x01}

// LoadPTX reads and parses a PTX file
func LoadPTX(filePath string) (*ptx.PtxFile, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if len(data) < 4 || !bytes.Equal(data[:4], MagicHeader) {
		return nil, errors.New("invalid PTX magic header")
	}

	// Experimental: Try skipping 5 bytes if 4 fails?
	// Based on hexdump showing AB at byte 4 (0-indexed 4, 1-indexed 5)
	// PTX\x01 (0,1,2,3). Byte 4 is AB.
	// 0x08 is at Byte 5.
	// Tag 1 (08) -> Byte 5.
	// So we should skip 5 bytes.
	payload := data[5:]
	ptxFile := &ptx.PtxFile{}
	if err := proto.Unmarshal(payload, ptxFile); err != nil {
		return nil, fmt.Errorf("failed to parse PTX protobuf: %w", err)
	}

	return ptxFile, nil
}
