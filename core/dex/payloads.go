// Package dex provides DEX file payload parsing and code analysis.
// This file implements fill-array-data, packed-switch, and sparse-switch payloads.
package dex

import (
	"encoding/binary"
	"fmt"
)

// FillArrayDataPayload represents a fill-array-data-payload instruction.
type FillArrayDataPayload struct {
	Offset       uint32
	ElementWidth uint16
	Size         uint32
	Data         []byte
}

// GetLength returns the total byte length of this payload.
func (p *FillArrayDataPayload) GetLength() int {
	// header(4) + width(2) + size(4) + data
	dataLen := int(p.Size) * int(p.ElementWidth)
	if dataLen%2 != 0 {
		dataLen++
	}
	return 8 + dataLen
}

// GetElement returns the element at the given index as a byte slice.
func (p *FillArrayDataPayload) GetElement(idx uint32) []byte {
	if idx >= p.Size {
		return nil
	}
	start := idx * uint32(p.ElementWidth)
	end := start + uint32(p.ElementWidth)
	if int(end) > len(p.Data) {
		return nil
	}
	return p.Data[start:end]
}

// GetElements returns all elements as byte slices.
func (p *FillArrayDataPayload) GetElements() [][]byte {
	elements := make([][]byte, p.Size)
	for i := uint32(0); i < p.Size; i++ {
		elements[i] = p.GetElement(i)
	}
	return elements
}

// String returns a human-readable representation.
func (p *FillArrayDataPayload) String() string {
	return fmt.Sprintf("fill-array-data-payload width=%d size=%d", p.ElementWidth, p.Size)
}

// PackedSwitchPayload represents a packed-switch-payload instruction.
type PackedSwitchPayload struct {
	Offset    uint32
	Size      uint16
	FirstKey  int32
	Targets   []int32
}

// GetLength returns the total byte length of this payload.
func (p *PackedSwitchPayload) GetLength() int {
	// header(4) + size(2) + first_key(4) + targets(size*4)
	return 8 + len(p.Targets)*4
}

// GetKeys returns the computed keys (first_key + index).
func (p *PackedSwitchPayload) GetKeys() []int32 {
	keys := make([]int32, len(p.Targets))
	for i := range p.Targets {
		keys[i] = p.FirstKey + int32(i)
	}
	return keys
}

// GetTargetForKey returns the branch target for a given key value.
func (p *PackedSwitchPayload) GetTargetForKey(key int32) (uint32, bool) {
	idx := key - p.FirstKey
	if idx < 0 || int(idx) >= len(p.Targets) {
		return 0, false
	}
	return uint32(int32(p.Offset) + p.Targets[idx]), true
}

// GetAllTargets returns all branch target addresses (absolute).
func (p *PackedSwitchPayload) GetAllTargets() []uint32 {
	targets := make([]uint32, len(p.Targets))
	for i, t := range p.Targets {
		targets[i] = uint32(int32(p.Offset) + t)
	}
	return targets
}

// String returns a human-readable representation.
func (p *PackedSwitchPayload) String() string {
	return fmt.Sprintf("packed-switch-payload size=%d first_key=%d", p.Size, p.FirstKey)
}

// SparseSwitchPayload represents a sparse-switch-payload instruction.
type SparseSwitchPayload struct {
	Offset  uint32
	Size    uint16
	Keys    []int32
	Targets []int32
}

// GetLength returns the total byte length of this payload.
func (p *SparseSwitchPayload) GetLength() int {
	// header(4) + size(2) + keys(size*4) + targets(size*4)
	return 4 + 2 + len(p.Keys)*4 + len(p.Targets)*4
}

// GetTargetForKey returns the branch target for a given key value.
func (p *SparseSwitchPayload) GetTargetForKey(key int32) (uint32, bool) {
	for i, k := range p.Keys {
		if k == key {
			return uint32(int32(p.Offset) + p.Targets[i]), true
		}
	}
	return 0, false
}

// GetAllTargets returns all branch target addresses (absolute).
func (p *SparseSwitchPayload) GetAllTargets() []uint32 {
	targets := make([]uint32, len(p.Targets))
	for i, t := range p.Targets {
		targets[i] = uint32(int32(p.Offset) + t)
	}
	return targets
}

// String returns a human-readable representation.
func (p *SparseSwitchPayload) String() string {
	return fmt.Sprintf("sparse-switch-payload size=%d", p.Size)
}

// ParseFillArrayDataPayload parses a fill-array-data-payload from raw bytes.
func ParseFillArrayDataPayload(data []byte, offset uint32) (*FillArrayDataPayload, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("fill-array-data: too short")
	}

	payload := &FillArrayDataPayload{Offset: offset}

	// ident = 0x0300 (fill-array-data)
	ident := binary.LittleEndian.Uint16(data[0:2])
	if ident != 0x0300 {
		return nil, fmt.Errorf("fill-array-data: invalid ident 0x%04x", ident)
	}

	payload.ElementWidth = binary.LittleEndian.Uint16(data[2:4])
	payload.Size = binary.LittleEndian.Uint32(data[4:8])

	dataLen := int(payload.Size) * int(payload.ElementWidth)
	if 8+dataLen > len(data) {
		return nil, fmt.Errorf("fill-array-data: data truncated")
	}

	payload.Data = make([]byte, dataLen)
	copy(payload.Data, data[8:8+dataLen])

	return payload, nil
}

// ParsePackedSwitchPayload parses a packed-switch-payload from raw bytes.
func ParsePackedSwitchPayload(data []byte, offset uint32) (*PackedSwitchPayload, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packed-switch: too short")
	}

	payload := &PackedSwitchPayload{Offset: offset}

	// ident = 0x0100 (packed-switch)
	ident := binary.LittleEndian.Uint16(data[0:2])
	if ident != 0x0100 {
		return nil, fmt.Errorf("packed-switch: invalid ident 0x%04x", ident)
	}

	payload.Size = binary.LittleEndian.Uint16(data[2:4])
	payload.FirstKey = int32(binary.LittleEndian.Uint32(data[4:8]))

	targetsSize := int(payload.Size) * 4
	if 8+targetsSize > len(data) {
		return nil, fmt.Errorf("packed-switch: targets truncated")
	}

	payload.Targets = make([]int32, payload.Size)
	for i := uint16(0); i < payload.Size; i++ {
		off := 8 + int(i)*4
		payload.Targets[i] = int32(binary.LittleEndian.Uint32(data[off : off+4]))
	}

	return payload, nil
}

// ParseSparseSwitchPayload parses a sparse-switch-payload from raw bytes.
func ParseSparseSwitchPayload(data []byte, offset uint32) (*SparseSwitchPayload, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("sparse-switch: too short")
	}

	payload := &SparseSwitchPayload{Offset: offset}

	// ident = 0x0200 (sparse-switch)
	ident := binary.LittleEndian.Uint16(data[0:2])
	if ident != 0x0200 {
		return nil, fmt.Errorf("sparse-switch: invalid ident 0x%04x", ident)
	}

	payload.Size = binary.LittleEndian.Uint16(data[2:4])

	keysSize := int(payload.Size) * 4
	targetsSize := int(payload.Size) * 4
	if 4+keysSize+targetsSize > len(data) {
		return nil, fmt.Errorf("sparse-switch: data truncated")
	}

	// Read keys
	payload.Keys = make([]int32, payload.Size)
	for i := uint16(0); i < payload.Size; i++ {
		off := 4 + int(i)*4
		payload.Keys[i] = int32(binary.LittleEndian.Uint32(data[off : off+4]))
	}

	// Read targets
	payload.Targets = make([]int32, payload.Size)
	for i := uint16(0); i < payload.Size; i++ {
		off := 4 + int(payload.Size)*4 + int(i)*4
		payload.Targets[i] = int32(binary.LittleEndian.Uint32(data[off : off+4]))
	}

	return payload, nil
}
