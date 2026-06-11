// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/efitcg2 authors. All rights reserved.

// Package efitcg2 implements a TPM 2.0 github.com/go-tpm2/common.Transport
// backed by the UEFI EFI_TCG2_PROTOCOL, so that go-tpm2's command layer can
// drive a firmware TPM while the machine is still in Boot Services.
//
// Motivation. Under a pre-ExitBootServices UEFI loader (for example a
// TamaGo + UEFI image running under OVMF), the TPM is owned by firmware and
// reached through the EFI_TCG2_PROTOCOL, not through raw TIS/CRB MMIO. The
// firmware has already established locality, banks, and the event log;
// touching the TIS/CRB register file directly at that point is wrong and
// races the firmware. EFI_TCG2_PROTOCOL.SubmitCommand is the supported way
// to pass a marshaled TPM 2.0 command to the firmware TPM, and
// HashLogExtendEvent is the supported measured-boot primitive (it extends a
// PCR *and* appends a TCG event-log record in one firmware call).
//
// Specification. The protocol is defined by the TCG "EFI Protocol
// Specification, Family 2.0" (a.k.a. the TCG EFI Protocol Specification),
// clause "EFI_TCG2_PROTOCOL", and surfaced in the UEFI specification. Every
// GUID, method order, structure layout, EFI_STATUS value, and flag below is
// cited inline to that specification. Items the spec leaves to the ABI/
// platform (vtable byte offsets, struct field packing/alignment) are marked
// "// INFERRED:" for the OVMF validation step to confirm.
//
// Dependency discipline. go-tpm2 must remain free of any UEFI/TamaGo
// dependency. This package therefore never imports an EFI runtime, never
// dereferences a protocol pointer, and never uses package unsafe: it takes
// an INJECTED firmware-call mechanism (a Caller) that the loader implements.
// The loader owns the protocol pointer and the architecture-specific EFI
// calling convention; efitcg2 only marshals buffers, interprets results, and
// satisfies common.Transport. This mirrors how go-tpm2/tis and go-tpm2/crb
// take an injected common.Regs rather than mapping MMIO themselves.
//
// Conventions: pure Go, CGO_ENABLED=0, no architecture-specific assembly,
// BSD-3-Clause on every file, 100% statement coverage, and GOWORK=off.
package efitcg2

import (
	"github.com/go-tpm2/common"
)

// GUID is a UEFI GUID: an EFI_GUID. UEFI represents it as a 32-bit Data1,
// two 16-bit Data2/Data3, and an 8-byte Data4, stored in memory MIXED-
// ENDIAN (Data1..Data3 little-endian, Data4 as-is). This Go value is the
// canonical field decomposition; the loader is responsible for laying it out
// in guest memory in the EFI_GUID byte order when it calls LocateProtocol.
// UEFI specification, "EFI_GUID" / appendix "GUID and Time Formats".
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// TCG2ProtocolGUID is EFI_TCG2_PROTOCOL_GUID,
// 607f766c-7455-42be-930b-e4d76db2720f. The loader passes this to
// EFI Boot Services LocateProtocol to obtain the EFI_TCG2_PROTOCOL
// interface pointer it then wires into a Caller. TCG "EFI Protocol
// Specification", clause "EFI_TCG2_PROTOCOL", "#define
// EFI_TCG2_PROTOCOL_GUID".
var TCG2ProtocolGUID = GUID{
	Data1: 0x607f766c,
	Data2: 0x7455,
	Data3: 0x42be,
	Data4: [8]byte{0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f},
}

// Method indices into the EFI_TCG2_PROTOCOL function table, in declaration
// order. They are exported only as a reference for a loader that implements
// Caller as a single low-level Call(method, args...) dispatcher rather than
// the high-level two-method interface; efitcg2 itself never indexes the
// vtable (it has no protocol pointer). TCG "EFI Protocol Specification",
// clause "EFI_TCG2_PROTOCOL", the EFI_TCG2_PROTOCOL structure (member
// order).
//
// INFERRED: that these ordinals map to fixed pointer-width vtable byte
// offsets (ordinal*sizeof(void*)) in the firmware's protocol structure. The
// declaration ORDER is fixed by the specification; the byte OFFSETS depend
// on the EFI ABI (pointer width, no padding between members) and must be
// confirmed against OVMF. efitcg2 does not rely on the offsets — only the
// loader's Caller does — but they are documented here for that loader.
const (
	MethodGetCapability                = 0
	MethodGetEventLog                  = 1
	MethodHashLogExtendEvent           = 2
	MethodSubmitCommand                = 3
	MethodGetActivePcrBanks            = 4
	MethodSetActivePcrBanks            = 5
	MethodGetResultOfSetActivePcrBanks = 6
)

// Caller is the INJECTED firmware-call mechanism the loader must implement.
// It is the entire UEFI-facing surface of efitcg2: the loader, which holds
// the EFI_TCG2_PROTOCOL pointer and the platform's EFI calling convention
// (efiCall), performs the actual firmware invocation; efitcg2 hands it
// already-marshaled buffers and interprets the returned EFI_STATUS.
//
// Contract. Each method invokes the correspondingly named EFI_TCG2_PROTOCOL
// member with This set to the located protocol pointer, and returns the
// raw EFI_STATUS as a uintptr (so the platform's native word width carries
// the high "error" bit unchanged; see statusError). A non-nil err reports a
// failure to perform the call itself (a marshaling/trap/transport problem on
// the loader side) and is distinct from a non-success status: when err is
// nil, status alone decides success. efitcg2 treats (status, err) as
// (EFI_STATUS, callError) and never inspects firmware memory directly.
//
//   - SubmitCommand(inputBlock, output): calls
//     EFI_TCG2_PROTOCOL.SubmitCommand(This, InputParameterBlockSize,
//     InputParameterBlock, OutputParameterBlockSize, OutputParameterBlock)
//     with InputParameterBlock = inputBlock and OutputParameterBlock = the
//     caller-allocated output buffer (length = OutputParameterBlockSize).
//     The firmware writes the TPM response into output in place. TCG "EFI
//     Protocol Specification", "EFI_TCG2_PROTOCOL.SubmitCommand()".
//
//   - HashLogExtendEvent(flags, dataToHash, event): calls
//     EFI_TCG2_PROTOCOL.HashLogExtendEvent(This, Flags, DataToHash,
//     DataToHashLen, EfiTcg2Event) with DataToHashLen = len(dataToHash) and
//     EfiTcg2Event = the serialized EFI_TCG2_EVENT in event (its leading
//     Size field already states its own length). TCG "EFI Protocol
//     Specification", "EFI_TCG2_PROTOCOL.HashLogExtendEvent()".
//
// The loader is free to implement Caller over a single low-level
// Call(method int, args ...uintptr) uintptr closure (using the Method*
// ordinals above) — that is an implementation detail efitcg2 does not see.
type Caller interface {
	// SubmitCommand passes one fully-marshaled TPM 2.0 command buffer to
	// the firmware TPM and receives the response into output, returning the
	// firmware's EFI_STATUS.
	SubmitCommand(inputBlock []byte, output []byte) (status uintptr, err error)
	// HashLogExtendEvent performs a measured-boot extend+log, returning the
	// firmware's EFI_STATUS.
	HashLogExtendEvent(flags uint64, dataToHash []byte, event []byte) (status uintptr, err error)
}

// CapabilityCaller is an OPTIONAL extension a Caller may also implement to
// report the firmware's EFI_TCG2_BOOT_SERVICE_CAPABILITY.MaxResponseSize.
// It is queried via EFI_TCG2_PROTOCOL.GetCapability (vtable index 0).
//
// Why it matters. SubmitCommand's OutputParameterBlockSize must not exceed
// the firmware's MaxResponseSize: a CRB/TIS-backed EFI_TCG2_PROTOCOL (e.g.
// OVMF) rejects an over-large output block with EFI_INVALID_PARAMETER before
// forwarding the command, so the whole readback fails. efitcg2 type-asserts a
// Caller to CapabilityCaller; when present and it returns a non-zero
// MaxResponseSize with a nil error, Send clamps its output block to
// min(requested, MaxResponseSize). A zero MaxResponseSize, an error, or a
// Caller that does not implement this interface leaves the requested size
// unchanged (the DefaultOutputSize fallback already fits a CRB ceiling).
//
// TCG "EFI Protocol Specification", "EFI_TCG2_PROTOCOL.GetCapability()" and
// "EFI_TCG2_BOOT_SERVICE_CAPABILITY" (its MaxResponseSize member).
type CapabilityCaller interface {
	// GetCapability reports the firmware's
	// EFI_TCG2_BOOT_SERVICE_CAPABILITY.MaxResponseSize (in bytes). A return
	// of (0, nil) means "not reported"; a non-nil err means the GetCapability
	// call itself failed — both cause Send to keep its requested size.
	GetCapability() (maxResponseSize uint32, err error)
}

// maxResponseSize queries a Caller for its firmware MaxResponseSize via the
// optional CapabilityCaller extension. It returns 0 when the Caller does not
// implement CapabilityCaller, when GetCapability errors, or when the firmware
// reports zero — i.e. 0 means "no advertised ceiling, use the requested
// size".
func maxResponseSize(c Caller) uint32 {
	cc, ok := c.(CapabilityCaller)
	if !ok {
		return 0
	}
	m, err := cc.GetCapability()
	if err != nil {
		return 0
	}
	return m
}

// EFI_STATUS values used by this package. EFI_STATUS is an architecture-
// width integer whose top bit marks an error; the low bits select the code.
// UEFI specification, appendix "Status Codes" (EFI_SUCCESS and the
// EFI_ERROR encodings). The numeric low parts below are the spec's
// canonical values; statusError applies the high "error" bit width-
// independently (see below).
const (
	// efiSuccess is EFI_SUCCESS (0). UEFI spec, "Status Codes".
	efiSuccess = 0
	// statusErrorBit is the most-significant bit of an EFI_STATUS, set on
	// every EFI_ERROR value. UEFI spec, appendix "Status Codes": "The
	// highest bit ... indicates an error." We test this bit on the returned
	// uintptr so the success/error decision is independent of the value's
	// low code, and a status is "success" iff it is exactly EFI_SUCCESS.
	//
	// EFI_STATUS is the native machine word, so the high bit sits at
	// bitWidth-1: bit 63 on a 64-bit platform (the OVMF/x86-64 target) and
	// bit 31 on a 32-bit one. ^uintptr(0) is all-ones of exactly that
	// width, so shifting it right by one gives a mask with the top bit
	// clear; XOR-ing back recovers just the top bit.
	statusErrorBit = ^uintptr(0) ^ (^uintptr(0) >> 1)
)

// EFI_STATUS low codes, named for the errors this package maps. UEFI
// specification, appendix "Status Codes", table "EFI_STATUS Error Codes
// (High Bit Set)". On a given platform the full EFI_STATUS is
// statusErrorBit | <code>.
const (
	codeInvalidParameter = 0x02 // EFI_INVALID_PARAMETER
	codeBufferTooSmall   = 0x05 // EFI_BUFFER_TOO_SMALL
	codeDeviceError      = 0x07 // EFI_DEVICE_ERROR
	codeNotFound         = 0x0E // EFI_NOT_FOUND
)

// Error sentinels, typed as common.Error so callers may compare with ==.
const (
	// ErrInvalidParameter maps EFI_INVALID_PARAMETER.
	ErrInvalidParameter = common.Error("efitcg2: EFI_INVALID_PARAMETER")
	// ErrBufferTooSmall maps EFI_BUFFER_TOO_SMALL. From SubmitCommand it
	// means the response did not fit OutputParameterBlockSize.
	ErrBufferTooSmall = common.Error("efitcg2: EFI_BUFFER_TOO_SMALL")
	// ErrDeviceError maps EFI_DEVICE_ERROR.
	ErrDeviceError = common.Error("efitcg2: EFI_DEVICE_ERROR")
	// ErrNotFound maps EFI_NOT_FOUND.
	ErrNotFound = common.Error("efitcg2: EFI_NOT_FOUND")
	// ErrStatus is returned for any other non-success EFI_STATUS.
	ErrStatus = common.Error("efitcg2: firmware returned a non-success EFI_STATUS")
	// ErrShortResponse is returned when the firmware reports success but the
	// response buffer is smaller than a TPM 2.0 header.
	ErrShortResponse = common.Error("efitcg2: response shorter than TPM header")
	// ErrResponseTooLarge is returned when the response's declared
	// responseSize exceeds the output buffer the firmware was given.
	ErrResponseTooLarge = common.Error("efitcg2: response larger than output buffer")
)

// DefaultOutputSize is the OutputParameterBlock size efitcg2 allocates for a
// SubmitCommand when no explicit ceiling is configured and the Caller does
// not advertise an EFI_TCG2_BOOT_SERVICE_CAPABILITY.MaxResponseSize (see
// CapabilityCaller). It is 0x1000-0x80 = 3968: the realistic CRB/TIS ceiling
// a firmware TPM exposes through SubmitCommand. TCG "EFI Protocol
// Specification", "EFI_TCG2_PROTOCOL.SubmitCommand()" (the caller sizes the
// output block).
//
// INFERRED, NOW CONFIRMED ON OVMF: the original 4096 was too LARGE, not too
// small. OVMF's CRB-backed EFI_TCG2_PROTOCOL advertises
// MaxResponseSize = 0xF80 = 3968 and rejects any SubmitCommand whose
// OutputParameterBlockSize exceeds it with EFI_INVALID_PARAMETER — before it
// ever forwards the command — so a 4096-byte block made every readback
// (e.g. PCRRead after a HashLogExtendEvent) fail. 3968 is the firmware-proven
// maximum (an output block <= 3968 succeeds); when the Caller implements
// CapabilityCaller, Send uses min(requested, MaxResponseSize) instead and
// this default is only the fallback for Callers that cannot report it.
const DefaultOutputSize = 3968

// statusError maps a raw EFI_STATUS (as returned by a Caller) and a Caller
// transport error to a Go error. err (a failure to perform the call) takes
// precedence; then EFI_SUCCESS yields nil; then the known EFI_ERROR codes
// map to their sentinels; any other non-success status yields ErrStatus.
// UEFI spec, appendix "Status Codes".
func statusError(status uintptr, err error) error {
	if err != nil {
		return err
	}
	if status == efiSuccess {
		return nil
	}
	switch status &^ statusErrorBit {
	case codeInvalidParameter:
		return ErrInvalidParameter
	case codeBufferTooSmall:
		return ErrBufferTooSmall
	case codeDeviceError:
		return ErrDeviceError
	case codeNotFound:
		return ErrNotFound
	default:
		return ErrStatus
	}
}

// TCG2 is a TPM 2.0 transport over EFI_TCG2_PROTOCOL. It holds only the
// injected Caller and the output-buffer size; it satisfies
// common.Transport.
type TCG2 struct {
	c          Caller
	outputSize int
}

// compile-time assertion that *TCG2 satisfies common.Transport.
var _ common.Transport = (*TCG2)(nil)

// New binds a TCG2 transport to the loader-provided Caller, allocating
// DefaultOutputSize bytes for each SubmitCommand response buffer.
func New(c Caller) *TCG2 {
	return NewWithOutputSize(c, DefaultOutputSize)
}

// NewWithOutputSize is New with an explicit OutputParameterBlock size (the
// ceiling on a single response). A non-positive size falls back to
// DefaultOutputSize.
func NewWithOutputSize(c Caller, outputSize int) *TCG2 {
	if outputSize <= 0 {
		outputSize = DefaultOutputSize
	}
	return &TCG2{c: c, outputSize: outputSize}
}

// Send transmits one fully-marshaled TPM 2.0 command buffer through
// EFI_TCG2_PROTOCOL.SubmitCommand and returns the full response buffer
// (header + params), trimmed to the TPM response's declared responseSize. It
// satisfies common.Transport.
//
// cmd becomes the InputParameterBlock; a freshly allocated OutputParameter-
// Block the firmware writes into is sized to t.outputSize, but never larger
// than the firmware's EFI_TCG2_BOOT_SERVICE_CAPABILITY.MaxResponseSize when
// the Caller advertises one via the optional CapabilityCaller extension: an
// over-large output block is rejected with EFI_INVALID_PARAMETER by CRB/TIS-
// backed firmware (e.g. OVMF) before the command is forwarded. So the block
// length is min(t.outputSize, MaxResponseSize) when MaxResponseSize is
// non-zero, else t.outputSize.
//
// On EFI_SUCCESS, Send parses the 10-byte TPM 2.0 response header
// (common.GetU32 of responseSize at offset 2), bounds-checks it against the
// header length and the output buffer, and returns the response sliced to
// that size. TCG "EFI Protocol Specification",
// "EFI_TCG2_PROTOCOL.SubmitCommand()" and "EFI_TCG2_PROTOCOL.GetCapability()";
// TCG "TPM 2.0 Part 1: Architecture", response header layout.
func (t *TCG2) Send(cmd []byte) (rsp []byte, err error) {
	outputSize := t.outputSize
	if m := maxResponseSize(t.c); m != 0 && int(m) < outputSize {
		outputSize = int(m)
	}
	out := make([]byte, outputSize)
	status, callErr := t.c.SubmitCommand(cmd, out)
	if e := statusError(status, callErr); e != nil {
		return nil, e
	}

	// responseSize is the u32 at offset 2 of the TPM 2.0 response header.
	size, ok := common.GetU32(out, 2)
	if !ok || size < common.HeaderSize {
		return nil, ErrShortResponse
	}
	if int(size) > len(out) {
		return nil, ErrResponseTooLarge
	}
	rsp = make([]byte, size)
	copy(rsp, out[:size])
	return rsp, nil
}

// EFI_TCG2_EVENT layout constants. TCG "EFI Protocol Specification",
// structures "EFI_TCG2_EVENT" and "EFI_TCG2_EVENT_HEADER":
//
//	typedef struct {
//	    UINT32                     Size;     // total size of this structure
//	    EFI_TCG2_EVENT_HEADER      Header;
//	    UINT8                      Event[];  // event data of (Size - 4 - HeaderSize)
//	} EFI_TCG2_EVENT;                        // packed, 1-byte aligned
//
//	typedef struct {
//	    UINT32                     HeaderSize;     // = sizeof(EFI_TCG2_EVENT_HEADER) = 14
//	    UINT16                     HeaderVersion;  // = EFI_TCG2_EVENT_HEADER_VERSION = 1
//	    TPMI_DH_PCR                PCRIndex;       // UINT32
//	    TPM_EVENTTYPE              EventType;      // UINT32
//	} EFI_TCG2_EVENT_HEADER;                       // packed, 1-byte aligned
//
// The EFI_TCG2_EVENT structures are LITTLE-ENDIAN, packed, and 1-byte
// aligned (UEFI's #pragma pack(1) convention for these protocol structures),
// which is why every multi-byte field below is laid out little-endian with
// no inter-field padding — unlike the big-endian TPM 2.0 wire encoding that
// Send carries.
const (
	// eventHeaderSize is sizeof(EFI_TCG2_EVENT_HEADER): HeaderSize(4) +
	// HeaderVersion(2) + PCRIndex(4) + EventType(4) = 14. TCG "EFI Protocol
	// Specification", "EFI_TCG2_EVENT_HEADER".
	eventHeaderSize = 14
	// eventHeaderVersion is EFI_TCG2_EVENT_HEADER_VERSION (1). TCG "EFI
	// Protocol Specification", "#define EFI_TCG2_EVENT_HEADER_VERSION 1".
	eventHeaderVersion = 1
	// eventOverhead is the fixed prefix before the variable Event[] data:
	// the outer Size field (4) plus the header (14) = 18.
	eventOverhead = 4 + eventHeaderSize
)

// HashLogExtendEvent flags. TCG "EFI Protocol Specification",
// "EFI_TCG2_PROTOCOL.HashLogExtendEvent()", the Flags parameter
// (EFI_TCG2_EVENT_LOG_FORMAT / PE_COFF_IMAGE bits).
const (
	// FlagNone requests the default behaviour: hash dataToHash, extend the
	// PCR, and append the event-log record.
	FlagNone uint64 = 0x0000000000000000
	// FlagPECOFFImage marks dataToHash as a loaded PE/COFF image so the
	// firmware applies the Authenticode-style measurement. TCG "EFI
	// Protocol Specification", "PE_COFF_IMAGE".
	FlagPECOFFImage uint64 = 0x0000000000000001
)

// buildEvent serializes an EFI_TCG2_EVENT for the given PCR, event type, and
// event description, little-endian and packed per the layout cited on the
// eventHeaderSize constants. The returned buffer's leading Size field equals
// its own total length (eventOverhead + len(eventDesc)).
func buildEvent(pcr uint32, eventType uint32, eventDesc []byte) []byte {
	size := uint32(eventOverhead + len(eventDesc))
	b := make([]byte, 0, size)
	b = putLE32(b, size)               // EFI_TCG2_EVENT.Size
	b = putLE32(b, eventHeaderSize)    // Header.HeaderSize
	b = putLE16(b, eventHeaderVersion) // Header.HeaderVersion
	b = putLE32(b, pcr)                // Header.PCRIndex
	b = putLE32(b, eventType)          // Header.EventType
	b = append(b, eventDesc...)        // Event[]
	return b
}

// MeasureToPCR performs a measured-boot extend-and-log: it hashes data into
// the firmware's active PCR banks for PCR pcr, appends a TCG event-log entry
// of type eventType carrying eventDesc, and returns any firmware error.
//
// Unlike a raw TPM2_PCR_Extend (which only mutates the PCR), this drives
// EFI_TCG2_PROTOCOL.HashLogExtendEvent, so the event is also recorded in the
// firmware's TCG event log for later attestation — the correct measured-boot
// primitive while in Boot Services. The flags select default vs PE/COFF
// hashing (see FlagNone / FlagPECOFFImage). TCG "EFI Protocol
// Specification", "EFI_TCG2_PROTOCOL.HashLogExtendEvent()".
func (t *TCG2) MeasureToPCR(pcr uint32, eventType uint32, data []byte, eventDesc []byte) error {
	return t.MeasureToPCRWithFlags(FlagNone, pcr, eventType, data, eventDesc)
}

// MeasureToPCRWithFlags is MeasureToPCR with an explicit HashLogExtendEvent
// Flags value.
func (t *TCG2) MeasureToPCRWithFlags(flags uint64, pcr uint32, eventType uint32, data []byte, eventDesc []byte) error {
	event := buildEvent(pcr, eventType, eventDesc)
	status, callErr := t.c.HashLogExtendEvent(flags, data, event)
	return statusError(status, callErr)
}

// --- little-endian put helpers ---
//
// The EFI_TCG2_EVENT structures are little-endian and packed (see the
// eventHeaderSize constants); these are the LE counterparts of common's
// big-endian PutU16/PutU32 and are intentionally local so this package adds
// no LE codec to the big-endian-only common package.

// putLE16 appends v to dst in little-endian order.
func putLE16(dst []byte, v uint16) []byte {
	return append(dst, byte(v), byte(v>>8))
}

// putLE32 appends v to dst in little-endian order.
func putLE32(dst []byte, v uint32) []byte {
	return append(dst, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
