package dex

import (
	"fmt"

	"github.com/goandroguard/goandroguard/internal/leb128"
)

// EncodedTypeAddrPair represents an encoded_type_addr_pair in a catch handler.
type EncodedTypeAddrPair struct {
	TypeIdx uint32 // Index into type_ids for the exception type to catch
	Addr    uint32 // Bytecode address of the handler
}

// String returns a human-readable representation.
func (p EncodedTypeAddrPair) String() string {
	return fmt.Sprintf("type@%d addr=0x%x", p.TypeIdx, p.Addr)
}

// EncodedCatchHandler represents an encoded_catch_handler.
type EncodedCatchHandlerFull struct {
	Size          int32 // Number of catch types (negative if has catch-all)
	Handlers      []EncodedTypeAddrPair
	CatchAllAddr  uint32  // Only present if Size <= 0
	HasCatchAll   bool
}

// GetHandlerCount returns the number of typed catch handlers.
func (h *EncodedCatchHandlerFull) GetHandlerCount() int {
	if h.Size < 0 {
		return int(-h.Size)
	}
	return int(h.Size)
}

// String returns a human-readable representation.
func (h *EncodedCatchHandlerFull) String() string {
	s := fmt.Sprintf("catch_handler size=%d", h.Size)
	for _, handler := range h.Handlers {
		s += fmt.Sprintf("\n  %s", handler.String())
	}
	if h.HasCatchAll {
		s += fmt.Sprintf("\n  catch_all=0x%x", h.CatchAllAddr)
	}
	return s
}

// EncodedCatchHandlerList represents a list of catch handlers.
type EncodedCatchHandlerListFull struct {
	Size    uint32
	Handlers []EncodedCatchHandlerFull
}

// ParseEncodedCatchHandlerList parses the full catch handler list.
func (d *DexFile) ParseEncodedCatchHandlerList(offset uint32) (*EncodedCatchHandlerListFull, error) {
	if offset >= uint32(len(d.raw)) {
		return nil, fmt.Errorf("catch handler list: out of bounds")
	}

	off := offset
	list := &EncodedCatchHandlerListFull{}

	// Read size (uleb128)
	size, n := leb128.ReadULEB128(d.raw[off:])
	list.Size = uint32(size)
	off += uint32(n)

	// Parse each handler
	list.Handlers = make([]EncodedCatchHandlerFull, list.Size)
	for i := uint32(0); i < list.Size; i++ {
		handler, n, err := d.parseEncodedCatchHandler(off)
		if err != nil {
			return list, fmt.Errorf("catch handler %d: %w", i, err)
		}
		list.Handlers[i] = *handler
		off += uint32(n)
	}

	return list, nil
}

// parseEncodedCatchHandler parses a single encoded_catch_handler.
func (d *DexFile) parseEncodedCatchHandler(offset uint32) (*EncodedCatchHandlerFull, int, error) {
	if offset >= uint32(len(d.raw)) {
		return nil, 0, fmt.Errorf("out of bounds")
	}

	off := offset
	handler := &EncodedCatchHandlerFull{}

	// Read size (sleb128)
	size, n := leb128.ReadSLEB128(d.raw[off:])
	handler.Size = int32(size)
	off += uint32(n)
	totalN := n

	handlerCount := handler.GetHandlerCount()

	// Parse handlers
	handler.Handlers = make([]EncodedTypeAddrPair, handlerCount)
	for i := 0; i < handlerCount; i++ {
		if off >= uint32(len(d.raw)) {
			return handler, totalN, nil
		}

		typeIdx, n1 := leb128.ReadULEB128(d.raw[off:])
		off += uint32(n1)
		totalN += n1

		addr, n2 := leb128.ReadULEB128(d.raw[off:])
		off += uint32(n2)
		totalN += n2

		handler.Handlers[i] = EncodedTypeAddrPair{
			TypeIdx: uint32(typeIdx),
			Addr:    uint32(addr),
		}
	}

	// Parse catch-all if present
	if handler.Size <= 0 {
		if off < uint32(len(d.raw)) {
			catchAllAddr, n := leb128.ReadULEB128(d.raw[off:])
			handler.CatchAllAddr = uint32(catchAllAddr)
			handler.HasCatchAll = true
			totalN += n
		}
	}

	return handler, totalN, nil
}

// GetCatchHandlerForTry returns the catch handler for a given try item.
func (list *EncodedCatchHandlerListFull) GetCatchHandlerForTry(handlerOffset uint16) *EncodedCatchHandlerFull {
	idx := int(handlerOffset)
	if idx >= 0 && idx < len(list.Handlers) {
		return &list.Handlers[idx]
	}
	return nil
}

// GetAllExceptionTypes returns all exception types caught by all handlers.
func (list *EncodedCatchHandlerListFull) GetAllExceptionTypes() []uint32 {
	var types []uint32
	seen := make(map[uint32]bool)
	for _, handler := range list.Handlers {
		for _, h := range handler.Handlers {
			if !seen[h.TypeIdx] {
				types = append(types, h.TypeIdx)
				seen[h.TypeIdx] = true
			}
		}
	}
	return types
}
