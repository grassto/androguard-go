// Package dex provides Dalvik bytecode opcode definitions.
// Reference: https://source.android.com/devices/tech/dalvik/bytecode
package dex

// Opcode represents a Dalvik bytecode instruction.
type Opcode struct {
	Name     string
	OpValue  uint8
	Format   InstructionFormat
	Kind     Kind
	Flags    OpcodeFlags
}

// InstructionFormat defines the format of a Dalvik instruction.
type InstructionFormat int

const (
	Format10x   InstructionFormat = iota // op
	Format12x                            // op vA, vB
	Format11n                            // op vA, #+B
	Format11x                            // op vA
	Format10t                            // op +AA
	Format20t                            // op +AAAA
	Format22x                            // op vAA, vBBBB
	Format21t                            // op vAA, +BBBB
	Format21s                            // op vAA, #+BBBB
	Format21h                            // op vAA, #+BBBB0000[00000000]
	Format21c                            // op vAA, type@BBBB
	Format23x                            // op vAA, vBB, vCC
	Format22b                            // op vAA, vBB, #+CC
	Format22t                            // op vA, vB, +CCCC
	Format22s                            // op vA, vB, #+CCCC
	Format22c                            // op vA, vB, type@CCCC
	Format32x                            // op vAAAA, vBBBB
	Format30t                            // op +AAAAAAAA
	Format31t                            // op vAA, +BBBBBBBB
	Format31i                            // op vAA, #+BBBBBBBB
	Format31c                            // op vAA, string@BBBBBBBB
	Format35c                            // op {vC, vD, vE, vF, vG}, meth@BBBB
	Format3rc                            // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
	Format45cc                            // op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH (DEX 038+)
	Format4rcc                            // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (DEX 038+)
	Format51l                            // op vAA, #+BBBBBBBBBBBBBBBB
)

// OpcodeFlags provides additional information about an opcode.
type OpcodeFlags int

const (
	FlagCanContinue    OpcodeFlags = 1 << iota // Can fall through
	FlagCanThrow                               // Can throw exceptions
	FlagCanReturn                              // Can return from method
	FlagInvoke                                 // Is an invoke instruction
	FlagSwitch                                 // Is a switch instruction
	FlagBranch                                 // Is a branch instruction
	FlagArrayOp                                // Is an array operation
	FlagFieldOp                                // Is a field operation
	FlagMethodOp                               // Is a method operation
)

// Dalvik opcodes - complete set
// Reference: https://source.android.com/devices/tech/dalvik/dalvik-bytecode
var Opcodes = map[uint8]Opcode{
	0x00: {"nop", 0x00, Format10x, 0, 0},
	0x01: {"move", 0x01, Format12x, 0, FlagCanContinue},
	0x02: {"move/from16", 0x02, Format22x, 0, FlagCanContinue},
	0x03: {"move/16", 0x03, Format32x, 0, FlagCanContinue},
	0x04: {"move-wide", 0x04, Format12x, 0, FlagCanContinue},
	0x05: {"move-wide/from16", 0x05, Format22x, 0, FlagCanContinue},
	0x06: {"move-wide/16", 0x06, Format32x, 0, FlagCanContinue},
	0x07: {"move-object", 0x07, Format12x, 0, FlagCanContinue},
	0x08: {"move-object/from16", 0x08, Format22x, 0, FlagCanContinue},
	0x09: {"move-object/16", 0x09, Format32x, 0, FlagCanContinue},
	0x0a: {"move-result", 0x0a, Format11x, 0, FlagCanContinue},
	0x0b: {"move-result-wide", 0x0b, Format11x, 0, FlagCanContinue},
	0x0c: {"move-result-object", 0x0c, Format11x, 0, FlagCanContinue},
	0x0d: {"move-exception", 0x0d, Format11x, 0, FlagCanContinue},
	0x0e: {"return-void", 0x0e, Format10x, 0, FlagCanReturn},
	0x0f: {"return", 0x0f, Format11x, 0, FlagCanReturn},
	0x10: {"return-wide", 0x10, Format11x, 0, FlagCanReturn},
	0x11: {"return-object", 0x11, Format11x, 0, FlagCanReturn},
	0x12: {"const/4", 0x12, Format11n, 0, FlagCanContinue},
	0x13: {"const/16", 0x13, Format21s, 0, FlagCanContinue},
	0x14: {"const", 0x14, Format31i, 0, FlagCanContinue},
	0x15: {"const/high16", 0x15, Format21h, 0, FlagCanContinue},
	0x16: {"const-wide/16", 0x16, Format21s, 0, FlagCanContinue},
	0x17: {"const-wide/32", 0x17, Format31i, 0, FlagCanContinue},
	0x18: {"const-wide", 0x18, Format51l, 0, FlagCanContinue},
	0x19: {"const-wide/high16", 0x19, Format21h, 0, FlagCanContinue},
	0x1a: {"const-string", 0x1a, Format21c, KindSTRING, FlagCanContinue | FlagCanThrow},
	0x1b: {"const-string/jumbo", 0x1b, Format31c, KindSTRING, FlagCanContinue | FlagCanThrow},
	0x1c: {"const-class", 0x1c, Format21c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x1d: {"monitor-enter", 0x1d, Format11x, 0, FlagCanContinue | FlagCanThrow},
	0x1e: {"monitor-exit", 0x1e, Format11x, 0, FlagCanContinue | FlagCanThrow},
	0x1f: {"check-cast", 0x1f, Format21c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x20: {"instance-of", 0x20, Format22c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x21: {"array-length", 0x21, Format12x, 0, FlagCanContinue | FlagCanThrow},
	0x22: {"new-instance", 0x22, Format21c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x23: {"new-array", 0x23, Format22c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x24: {"filled-new-array", 0x24, Format35c, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x25: {"filled-new-array/range", 0x25, Format3rc, KindTYPE, FlagCanContinue | FlagCanThrow},
	0x26: {"fill-array-data", 0x26, Format31t, 0, FlagCanContinue},
	0x27: {"throw", 0x27, Format11x, 0, FlagCanThrow},
	0x28: {"goto", 0x28, Format10t, 0, FlagCanContinue},
	0x29: {"goto/16", 0x29, Format20t, 0, FlagCanContinue},
	0x2a: {"goto/32", 0x2a, Format30t, 0, FlagCanContinue},
	0x2b: {"packed-switch", 0x2b, Format31t, 0, FlagCanContinue | FlagSwitch},
	0x2c: {"sparse-switch", 0x2c, Format31t, 0, FlagCanContinue | FlagSwitch},
	// Compare operations
	0x2d: {"cmpl-float", 0x2d, Format23x, 0, FlagCanContinue},
	0x2e: {"cmpg-float", 0x2e, Format23x, 0, FlagCanContinue},
	0x2f: {"cmpl-double", 0x2f, Format23x, 0, FlagCanContinue},
	0x30: {"cmpg-double", 0x30, Format23x, 0, FlagCanContinue},
	0x31: {"cmp-long", 0x31, Format23x, 0, FlagCanContinue},
	// Branch operations
	0x32: {"if-eq", 0x32, Format22t, 0, FlagCanContinue | FlagBranch},
	0x33: {"if-ne", 0x33, Format22t, 0, FlagCanContinue | FlagBranch},
	0x34: {"if-lt", 0x34, Format22t, 0, FlagCanContinue | FlagBranch},
	0x35: {"if-ge", 0x35, Format22t, 0, FlagCanContinue | FlagBranch},
	0x36: {"if-gt", 0x36, Format22t, 0, FlagCanContinue | FlagBranch},
	0x37: {"if-le", 0x37, Format22t, 0, FlagCanContinue | FlagBranch},
	0x38: {"if-eqz", 0x38, Format21t, 0, FlagCanContinue | FlagBranch},
	0x39: {"if-nez", 0x39, Format21t, 0, FlagCanContinue | FlagBranch},
	0x3a: {"if-ltz", 0x3a, Format21t, 0, FlagCanContinue | FlagBranch},
	0x3b: {"if-gez", 0x3b, Format21t, 0, FlagCanContinue | FlagBranch},
	0x3c: {"if-gtz", 0x3c, Format21t, 0, FlagCanContinue | FlagBranch},
	0x3d: {"if-lez", 0x3d, Format21t, 0, FlagCanContinue | FlagBranch},
	// Unused
	0x3e: {"unused-3e", 0x3e, Format10x, 0, 0},
	0x3f: {"unused-3f", 0x3f, Format10x, 0, 0},
	0x40: {"unused-40", 0x40, Format10x, 0, 0},
	0x41: {"unused-41", 0x41, Format10x, 0, 0},
	0x42: {"unused-42", 0x42, Format10x, 0, 0},
	0x43: {"unused-43", 0x43, Format10x, 0, 0},
	// Array operations
	0x44: {"aget", 0x44, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x45: {"aget-wide", 0x45, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x46: {"aget-object", 0x46, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x47: {"aget-boolean", 0x47, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x48: {"aget-byte", 0x48, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x49: {"aget-char", 0x49, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4a: {"aget-short", 0x4a, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4b: {"aput", 0x4b, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4c: {"aput-wide", 0x4c, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4d: {"aput-object", 0x4d, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4e: {"aput-boolean", 0x4e, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x4f: {"aput-byte", 0x4f, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x50: {"aput-char", 0x50, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	0x51: {"aput-short", 0x51, Format23x, 0, FlagCanContinue | FlagCanThrow | FlagArrayOp},
	// Instance field operations
	0x52: {"iget", 0x52, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x53: {"iget-wide", 0x53, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x54: {"iget-object", 0x54, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x55: {"iget-boolean", 0x55, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x56: {"iget-byte", 0x56, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x57: {"iget-char", 0x57, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x58: {"iget-short", 0x58, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x59: {"iput", 0x59, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5a: {"iput-wide", 0x5a, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5b: {"iput-object", 0x5b, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5c: {"iput-boolean", 0x5c, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5d: {"iput-byte", 0x5d, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5e: {"iput-char", 0x5e, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x5f: {"iput-short", 0x5f, Format22c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	// Static field operations
	0x60: {"sget", 0x60, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x61: {"sget-wide", 0x61, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x62: {"sget-object", 0x62, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x63: {"sget-boolean", 0x63, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x64: {"sget-byte", 0x64, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x65: {"sget-char", 0x65, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x66: {"sget-short", 0x66, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x67: {"sput", 0x67, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x68: {"sput-wide", 0x68, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x69: {"sput-object", 0x69, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x6a: {"sput-boolean", 0x6a, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x6b: {"sput-byte", 0x6b, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x6c: {"sput-char", 0x6c, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	0x6d: {"sput-short", 0x6d, Format21c, KindFIELD, FlagCanContinue | FlagCanThrow | FlagFieldOp},
	// Invoke operations
	0x6e: {"invoke-virtual", 0x6e, Format35c, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x6f: {"invoke-super", 0x6f, Format35c, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x70: {"invoke-direct", 0x70, Format35c, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x71: {"invoke-static", 0x71, Format35c, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x72: {"invoke-interface", 0x72, Format35c, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x73: {"unused-73", 0x73, Format10x, 0, 0},
	0x74: {"invoke-virtual/range", 0x74, Format3rc, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x75: {"invoke-super/range", 0x75, Format3rc, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x76: {"invoke-direct/range", 0x76, Format3rc, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x77: {"invoke-static/range", 0x77, Format3rc, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x78: {"invoke-interface/range", 0x78, Format3rc, KindMETH, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0x79: {"unused-79", 0x79, Format10x, 0, 0},
	0x7a: {"unused-7a", 0x7a, Format10x, 0, 0},
	// Unary operations
	0x7b: {"neg-int", 0x7b, Format12x, 0, FlagCanContinue},
	0x7c: {"not-int", 0x7c, Format12x, 0, FlagCanContinue},
	0x7d: {"neg-long", 0x7d, Format12x, 0, FlagCanContinue},
	0x7e: {"not-long", 0x7e, Format12x, 0, FlagCanContinue},
	0x7f: {"neg-float", 0x7f, Format12x, 0, FlagCanContinue},
	0x80: {"neg-double", 0x80, Format12x, 0, FlagCanContinue},
	0x81: {"int-to-long", 0x81, Format12x, 0, FlagCanContinue},
	0x82: {"int-to-float", 0x82, Format12x, 0, FlagCanContinue},
	0x83: {"int-to-double", 0x83, Format12x, 0, FlagCanContinue},
	0x84: {"long-to-int", 0x84, Format12x, 0, FlagCanContinue},
	0x85: {"long-to-float", 0x85, Format12x, 0, FlagCanContinue},
	0x86: {"long-to-double", 0x86, Format12x, 0, FlagCanContinue},
	0x87: {"float-to-int", 0x87, Format12x, 0, FlagCanContinue},
	0x88: {"float-to-long", 0x88, Format12x, 0, FlagCanContinue},
	0x89: {"float-to-double", 0x89, Format12x, 0, FlagCanContinue},
	0x8a: {"double-to-int", 0x8a, Format12x, 0, FlagCanContinue},
	0x8b: {"double-to-long", 0x8b, Format12x, 0, FlagCanContinue},
	0x8c: {"double-to-float", 0x8c, Format12x, 0, FlagCanContinue},
	0x8d: {"int-to-byte", 0x8d, Format12x, 0, FlagCanContinue},
	0x8e: {"int-to-char", 0x8e, Format12x, 0, FlagCanContinue},
	0x8f: {"int-to-short", 0x8f, Format12x, 0, FlagCanContinue},
	// Binary operations
	0x90: {"add-int", 0x90, Format23x, 0, FlagCanContinue},
	0x91: {"sub-int", 0x91, Format23x, 0, FlagCanContinue},
	0x92: {"mul-int", 0x92, Format23x, 0, FlagCanContinue},
	0x93: {"div-int", 0x93, Format23x, 0, FlagCanContinue | FlagCanThrow},
	0x94: {"rem-int", 0x94, Format23x, 0, FlagCanContinue | FlagCanThrow},
	0x95: {"and-int", 0x95, Format23x, 0, FlagCanContinue},
	0x96: {"or-int", 0x96, Format23x, 0, FlagCanContinue},
	0x97: {"xor-int", 0x97, Format23x, 0, FlagCanContinue},
	0x98: {"shl-int", 0x98, Format23x, 0, FlagCanContinue},
	0x99: {"shr-int", 0x99, Format23x, 0, FlagCanContinue},
	0x9a: {"ushr-int", 0x9a, Format23x, 0, FlagCanContinue},
	0x9b: {"add-long", 0x9b, Format23x, 0, FlagCanContinue},
	0x9c: {"sub-long", 0x9c, Format23x, 0, FlagCanContinue},
	0x9d: {"mul-long", 0x9d, Format23x, 0, FlagCanContinue},
	0x9e: {"div-long", 0x9e, Format23x, 0, FlagCanContinue | FlagCanThrow},
	0x9f: {"rem-long", 0x9f, Format23x, 0, FlagCanContinue | FlagCanThrow},
	0xa0: {"and-long", 0xa0, Format23x, 0, FlagCanContinue},
	0xa1: {"or-long", 0xa1, Format23x, 0, FlagCanContinue},
	0xa2: {"xor-long", 0xa2, Format23x, 0, FlagCanContinue},
	0xa3: {"shl-long", 0xa3, Format23x, 0, FlagCanContinue},
	0xa4: {"shr-long", 0xa4, Format23x, 0, FlagCanContinue},
	0xa5: {"ushr-long", 0xa5, Format23x, 0, FlagCanContinue},
	0xa6: {"add-float", 0xa6, Format23x, 0, FlagCanContinue},
	0xa7: {"sub-float", 0xa7, Format23x, 0, FlagCanContinue},
	0xa8: {"mul-float", 0xa8, Format23x, 0, FlagCanContinue},
	0xa9: {"div-float", 0xa9, Format23x, 0, FlagCanContinue},
	0xaa: {"rem-float", 0xaa, Format23x, 0, FlagCanContinue},
	0xab: {"add-double", 0xab, Format23x, 0, FlagCanContinue},
	0xac: {"sub-double", 0xac, Format23x, 0, FlagCanContinue},
	0xad: {"mul-double", 0xad, Format23x, 0, FlagCanContinue},
	0xae: {"div-double", 0xae, Format23x, 0, FlagCanContinue},
	0xaf: {"rem-double", 0xaf, Format23x, 0, FlagCanContinue},
	// Binary operations with 2addr
	0xb0: {"add-int/2addr", 0xb0, Format12x, 0, FlagCanContinue},
	0xb1: {"sub-int/2addr", 0xb1, Format12x, 0, FlagCanContinue},
	0xb2: {"mul-int/2addr", 0xb2, Format12x, 0, FlagCanContinue},
	0xb3: {"div-int/2addr", 0xb3, Format12x, 0, FlagCanContinue | FlagCanThrow},
	0xb4: {"rem-int/2addr", 0xb4, Format12x, 0, FlagCanContinue | FlagCanThrow},
	0xb5: {"and-int/2addr", 0xb5, Format12x, 0, FlagCanContinue},
	0xb6: {"or-int/2addr", 0xb6, Format12x, 0, FlagCanContinue},
	0xb7: {"xor-int/2addr", 0xb7, Format12x, 0, FlagCanContinue},
	0xb8: {"shl-int/2addr", 0xb8, Format12x, 0, FlagCanContinue},
	0xb9: {"shr-int/2addr", 0xb9, Format12x, 0, FlagCanContinue},
	0xba: {"ushr-int/2addr", 0xba, Format12x, 0, FlagCanContinue},
	0xbb: {"add-long/2addr", 0xbb, Format12x, 0, FlagCanContinue},
	0xbc: {"sub-long/2addr", 0xbc, Format12x, 0, FlagCanContinue},
	0xbd: {"mul-long/2addr", 0xbd, Format12x, 0, FlagCanContinue},
	0xbe: {"div-long/2addr", 0xbe, Format12x, 0, FlagCanContinue | FlagCanThrow},
	0xbf: {"rem-long/2addr", 0xbf, Format12x, 0, FlagCanContinue | FlagCanThrow},
	0xc0: {"and-long/2addr", 0xc0, Format12x, 0, FlagCanContinue},
	0xc1: {"or-long/2addr", 0xc1, Format12x, 0, FlagCanContinue},
	0xc2: {"xor-long/2addr", 0xc2, Format12x, 0, FlagCanContinue},
	0xc3: {"shl-long/2addr", 0xc3, Format12x, 0, FlagCanContinue},
	0xc4: {"shr-long/2addr", 0xc4, Format12x, 0, FlagCanContinue},
	0xc5: {"ushr-long/2addr", 0xc5, Format12x, 0, FlagCanContinue},
	0xc6: {"add-float/2addr", 0xc6, Format12x, 0, FlagCanContinue},
	0xc7: {"sub-float/2addr", 0xc7, Format12x, 0, FlagCanContinue},
	0xc8: {"mul-float/2addr", 0xc8, Format12x, 0, FlagCanContinue},
	0xc9: {"div-float/2addr", 0xc9, Format12x, 0, FlagCanContinue},
	0xca: {"rem-float/2addr", 0xca, Format12x, 0, FlagCanContinue},
	0xcb: {"add-double/2addr", 0xcb, Format12x, 0, FlagCanContinue},
	0xcc: {"sub-double/2addr", 0xcc, Format12x, 0, FlagCanContinue},
	0xcd: {"mul-double/2addr", 0xcd, Format12x, 0, FlagCanContinue},
	0xce: {"div-double/2addr", 0xce, Format12x, 0, FlagCanContinue},
	0xcf: {"rem-double/2addr", 0xcf, Format12x, 0, FlagCanContinue},
	// Binary operations with lit16
	0xd0: {"add-int/lit16", 0xd0, Format22s, 0, FlagCanContinue},
	0xd1: {"rsub-int/lit16", 0xd1, Format22s, 0, FlagCanContinue},
	0xd2: {"mul-int/lit16", 0xd2, Format22s, 0, FlagCanContinue},
	0xd3: {"div-int/lit16", 0xd3, Format22s, 0, FlagCanContinue | FlagCanThrow},
	0xd4: {"rem-int/lit16", 0xd4, Format22s, 0, FlagCanContinue | FlagCanThrow},
	0xd5: {"and-int/lit16", 0xd5, Format22s, 0, FlagCanContinue},
	0xd6: {"or-int/lit16", 0xd6, Format22s, 0, FlagCanContinue},
	0xd7: {"xor-int/lit16", 0xd7, Format22s, 0, FlagCanContinue},
	// Binary operations with lit8
	0xd8: {"add-int/lit8", 0xd8, Format22b, 0, FlagCanContinue},
	0xd9: {"rsub-int/lit8", 0xd9, Format22b, 0, FlagCanContinue},
	0xda: {"mul-int/lit8", 0xda, Format22b, 0, FlagCanContinue},
	0xdb: {"div-int/lit8", 0xdb, Format22b, 0, FlagCanContinue | FlagCanThrow},
	0xdc: {"rem-int/lit8", 0xdc, Format22b, 0, FlagCanContinue | FlagCanThrow},
	0xdd: {"and-int/lit8", 0xdd, Format22b, 0, FlagCanContinue},
	0xde: {"or-int/lit8", 0xde, Format22b, 0, FlagCanContinue},
	0xdf: {"xor-int/lit8", 0xdf, Format22b, 0, FlagCanContinue},
	0xe0: {"shl-int/lit8", 0xe0, Format22b, 0, FlagCanContinue},
	0xe1: {"shr-int/lit8", 0xe1, Format22b, 0, FlagCanContinue},
	0xe2: {"ushr-int/lit8", 0xe2, Format22b, 0, FlagCanContinue},
	// Unused (DEX 035-037)
	0xe3: {"unused-e3", 0xe3, Format10x, 0, 0},
	0xe4: {"unused-e4", 0xe4, Format10x, 0, 0},
	0xe5: {"unused-e5", 0xe5, Format10x, 0, 0},
	0xe6: {"unused-e6", 0xe6, Format10x, 0, 0},
	0xe7: {"unused-e7", 0xe7, Format10x, 0, 0},
	0xe8: {"unused-e8", 0xe8, Format10x, 0, 0},
	0xe9: {"unused-e9", 0xe9, Format10x, 0, 0},
	0xea: {"unused-ea", 0xea, Format10x, 0, 0},
	0xeb: {"unused-eb", 0xeb, Format10x, 0, 0},
	0xec: {"unused-ec", 0xec, Format10x, 0, 0},
	0xed: {"unused-ed", 0xed, Format10x, 0, 0},
	// DEX 038+ opcodes
	0xee: {"invoke-polymorphic", 0xee, Format45cc, KindMETH_PROTO, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0xef: {"invoke-polymorphic/range", 0xef, Format4rcc, KindMETH_PROTO, FlagCanContinue | FlagCanThrow | FlagInvoke | FlagMethodOp},
	0xf0: {"invoke-custom", 0xf0, Format35c, KindCALL_SITE, FlagCanContinue | FlagCanThrow | FlagInvoke},
	0xf1: {"invoke-custom/range", 0xf1, Format3rc, KindCALL_SITE, FlagCanContinue | FlagCanThrow | FlagInvoke},
	0xf2: {"const-method-handle", 0xf2, Format21c, 0, FlagCanContinue},
	0xf3: {"const-method-type", 0xf3, Format21c, KindPROTO, FlagCanContinue},
	// Unused
	0xf4: {"unused-f4", 0xf4, Format10x, 0, 0},
	0xf5: {"unused-f5", 0xf5, Format10x, 0, 0},
	0xf6: {"unused-f6", 0xf6, Format10x, 0, 0},
	0xf7: {"unused-f7", 0xf7, Format10x, 0, 0},
	0xf8: {"unused-f8", 0xf8, Format10x, 0, 0},
	0xf9: {"unused-f9", 0xf9, Format10x, 0, 0},
	// Packed switch / sparse switch payload
	0xfa: {"invoke-polymorphic/jumbo", 0xfa, Format10x, 0, 0}, // Only for DEX 040+
	0xfb: {"unused-fb", 0xfb, Format10x, 0, 0},
	0xfc: {"unused-fc", 0xfc, Format10x, 0, 0},
	0xfd: {"unused-fd", 0xfd, Format10x, 0, 0},
	0xfe: {"packed-switch-payload", 0xfe, Format10x, 0, 0},
	0xff: {"sparse-switch-payload", 0xff, Format10x, 0, 0},
}

// GetOpcodeName returns the name of an opcode by its value.
func GetOpcodeName(op uint8) string {
	if opcode, ok := Opcodes[op]; ok {
		return opcode.Name
	}
	return "unknown"
}

// GetOpcode returns the Opcode for a given value.
func GetOpcode(op uint8) (Opcode, bool) {
	if opcode, ok := Opcodes[op]; ok {
		return opcode, true
	}
	return Opcode{}, false
}

// InstructionFormat returns the instruction format string.
func (f InstructionFormat) String() string {
	switch f {
	case Format10x:
		return "10x"
	case Format12x:
		return "12x"
	case Format11n:
		return "11n"
	case Format11x:
		return "11x"
	case Format10t:
		return "10t"
	case Format20t:
		return "20t"
	case Format22x:
		return "22x"
	case Format21t:
		return "21t"
	case Format21s:
		return "21s"
	case Format21h:
		return "21h"
	case Format21c:
		return "21c"
	case Format23x:
		return "23x"
	case Format22b:
		return "22b"
	case Format22t:
		return "22t"
	case Format22s:
		return "22s"
	case Format22c:
		return "22c"
	case Format32x:
		return "32x"
	case Format30t:
		return "30t"
	case Format31t:
		return "31t"
	case Format31i:
		return "31i"
	case Format31c:
		return "31c"
	case Format35c:
		return "35c"
	case Format3rc:
		return "3rc"
	case Format45cc:
		return "45cc"
	case Format4rcc:
		return "4rcc"
	case Format51l:
		return "51l"
	default:
		return "unknown"
	}
}
