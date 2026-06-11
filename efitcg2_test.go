// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/efitcg2 authors. All rights reserved.

package efitcg2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-tpm2/common"
)

// fakeCaller is a test double for the injected firmware Caller. It records
// what efitcg2 hands it and returns canned (status, err) results, plus, for
// SubmitCommand, a canned response it copies into the firmware-owned output
// buffer (mimicking in-place firmware writes).
type fakeCaller struct {
	// recorded SubmitCommand inputs.
	subInput  []byte
	subOutLen int
	// canned SubmitCommand result.
	subResp   []byte // copied into output on success-shaped calls
	subStatus uintptr
	subErr    error

	// recorded HashLogExtendEvent inputs.
	hleFlags uint64
	hleData  []byte
	hleEvent []byte
	// canned HashLogExtendEvent result.
	hleStatus uintptr
	hleErr    error
}

func (f *fakeCaller) SubmitCommand(inputBlock []byte, output []byte) (uintptr, error) {
	f.subInput = append([]byte(nil), inputBlock...)
	f.subOutLen = len(output)
	if f.subResp != nil {
		copy(output, f.subResp)
	}
	return f.subStatus, f.subErr
}

func (f *fakeCaller) HashLogExtendEvent(flags uint64, dataToHash []byte, event []byte) (uintptr, error) {
	f.hleFlags = flags
	f.hleData = append([]byte(nil), dataToHash...)
	f.hleEvent = append([]byte(nil), event...)
	return f.hleStatus, f.hleErr
}

// capCaller is a fakeCaller that also implements CapabilityCaller, reporting
// a canned MaxResponseSize / GetCapability error so Send's output-block
// clamp can be exercised.
type capCaller struct {
	fakeCaller
	capMax uint32
	capErr error
}

func (c *capCaller) GetCapability() (uint32, error) {
	return c.capMax, c.capErr
}

// tpmResponse builds a minimal well-formed TPM 2.0 response buffer of the
// given total size (>= HeaderSize) with the responseSize field set to size.
func tpmResponse(size int, rc uint32) []byte {
	b := common.BuildCommand(uint16(common.TagNoSessions), rc, nil) // 10-byte header
	// BuildCommand sets size to 10; overwrite the size field to `size` and
	// pad to that length so the header's responseSize matches the buffer.
	for len(b) < size {
		b = append(b, 0xAA)
	}
	// rewrite size u32 at offset 2 to the declared size.
	b[2] = byte(size >> 24)
	b[3] = byte(size >> 16)
	b[4] = byte(size >> 8)
	b[5] = byte(size)
	return b
}

func TestTCG2ProtocolGUID(t *testing.T) {
	// 607f766c-7455-42be-930b-e4d76db2720f.
	if TCG2ProtocolGUID.Data1 != 0x607f766c ||
		TCG2ProtocolGUID.Data2 != 0x7455 ||
		TCG2ProtocolGUID.Data3 != 0x42be {
		t.Fatalf("GUID Data1-3 wrong: %#v", TCG2ProtocolGUID)
	}
	wantD4 := [8]byte{0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}
	if TCG2ProtocolGUID.Data4 != wantD4 {
		t.Fatalf("GUID Data4 = %x, want %x", TCG2ProtocolGUID.Data4, wantD4)
	}
}

func TestMethodOrdinals(t *testing.T) {
	// Declaration order per the EFI_TCG2_PROTOCOL structure.
	got := []int{
		MethodGetCapability, MethodGetEventLog, MethodHashLogExtendEvent,
		MethodSubmitCommand, MethodGetActivePcrBanks, MethodSetActivePcrBanks,
		MethodGetResultOfSetActivePcrBanks,
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("ordinal %d = %d, want %d", i, v, i)
		}
	}
}

func TestNewDefaults(t *testing.T) {
	f := &fakeCaller{}
	if got := New(f).outputSize; got != DefaultOutputSize {
		t.Fatalf("New outputSize = %d, want %d", got, DefaultOutputSize)
	}
	// non-positive sizes fall back to the default.
	if got := NewWithOutputSize(f, 0).outputSize; got != DefaultOutputSize {
		t.Fatalf("zero outputSize = %d, want %d", got, DefaultOutputSize)
	}
	if got := NewWithOutputSize(f, -7).outputSize; got != DefaultOutputSize {
		t.Fatalf("negative outputSize = %d, want %d", got, DefaultOutputSize)
	}
	if got := NewWithOutputSize(f, 256).outputSize; got != 256 {
		t.Fatalf("explicit outputSize = %d, want 256", got)
	}
}

func TestDefaultOutputSizeFitsCRBCeiling(t *testing.T) {
	// The firmware-proven CRB/TIS ceiling (OVMF MaxResponseSize = 0xF80).
	// DefaultOutputSize must not exceed it, or a default Send is rejected
	// with EFI_INVALID_PARAMETER before the command is forwarded.
	const crbCeiling = 0x1000 - 0x80 // 3968
	if DefaultOutputSize != crbCeiling {
		t.Fatalf("DefaultOutputSize = %d, want %d", DefaultOutputSize, crbCeiling)
	}
}

func TestSendClampsToMaxResponseSize(t *testing.T) {
	// A CapabilityCaller advertising MaxResponseSize < requested clamps the
	// OutputParameterBlock to MaxResponseSize (the min() picks the cap).
	resp := tpmResponse(24, uint32(common.RCSuccess))
	c := &capCaller{capMax: 100}
	c.subResp = resp
	c.subStatus = efiSuccess
	if _, err := NewWithOutputSize(c, 4096).Send([]byte("cmd")); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if c.subOutLen != 100 {
		t.Fatalf("output block len = %d, want 100 (clamped to MaxResponseSize)", c.subOutLen)
	}
}

func TestSendKeepsRequestedWhenSmaller(t *testing.T) {
	// MaxResponseSize >= requested leaves the requested size (the min() picks
	// the requested side).
	resp := tpmResponse(24, uint32(common.RCSuccess))
	c := &capCaller{capMax: 8192}
	c.subResp = resp
	c.subStatus = efiSuccess
	if _, err := NewWithOutputSize(c, 256).Send([]byte("cmd")); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if c.subOutLen != 256 {
		t.Fatalf("output block len = %d, want 256 (requested kept)", c.subOutLen)
	}
}

func TestSendCapabilityZeroFallsBack(t *testing.T) {
	// MaxResponseSize == 0 (not reported) leaves the requested size unchanged.
	resp := tpmResponse(24, uint32(common.RCSuccess))
	c := &capCaller{capMax: 0}
	c.subResp = resp
	c.subStatus = efiSuccess
	if _, err := NewWithOutputSize(c, 512).Send([]byte("cmd")); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if c.subOutLen != 512 {
		t.Fatalf("output block len = %d, want 512 (zero MaxResponseSize ignored)", c.subOutLen)
	}
}

func TestSendCapabilityErrorFallsBack(t *testing.T) {
	// GetCapability errors are treated as "not reported": requested kept.
	resp := tpmResponse(24, uint32(common.RCSuccess))
	c := &capCaller{capMax: 64, capErr: errors.New("getcap trap")}
	c.subResp = resp
	c.subStatus = efiSuccess
	if _, err := NewWithOutputSize(c, 512).Send([]byte("cmd")); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if c.subOutLen != 512 {
		t.Fatalf("output block len = %d, want 512 (GetCapability error ignored)", c.subOutLen)
	}
}

func TestSendNonCapabilityCallerKeepsRequested(t *testing.T) {
	// A plain Caller (no CapabilityCaller) is never clamped: the default Send
	// uses the full requested size. (maxResponseSize's !ok branch.)
	resp := tpmResponse(24, uint32(common.RCSuccess))
	f := &fakeCaller{subResp: resp, subStatus: efiSuccess}
	if _, err := New(f).Send([]byte("cmd")); err != nil {
		t.Fatalf("Send err = %v", err)
	}
	if f.subOutLen != DefaultOutputSize {
		t.Fatalf("output block len = %d, want %d", f.subOutLen, DefaultOutputSize)
	}
}

func TestSendSuccess(t *testing.T) {
	resp := tpmResponse(24, uint32(common.RCSuccess))
	f := &fakeCaller{subResp: resp, subStatus: efiSuccess}
	tpm := NewWithOutputSize(f, 64)

	cmd := common.BuildCommand(uint16(common.TagNoSessions),
		uint32(common.CCGetRandom), []byte{0x00, 0x08})
	got, err := tpm.Send(cmd)
	if err != nil {
		t.Fatalf("Send err = %v", err)
	}
	// The command was handed to SubmitCommand verbatim as the input block.
	if !bytes.Equal(f.subInput, cmd) {
		t.Fatalf("SubmitCommand input = %x, want %x", f.subInput, cmd)
	}
	// The output block was sized to the configured outputSize.
	if f.subOutLen != 64 {
		t.Fatalf("output block len = %d, want 64", f.subOutLen)
	}
	// The returned response is trimmed to responseSize (24), not 64.
	if len(got) != 24 {
		t.Fatalf("response len = %d, want 24", len(got))
	}
	if !bytes.Equal(got, resp[:24]) {
		t.Fatalf("response = %x, want %x", got, resp[:24])
	}
	// And it is a copy, not an alias of the firmware buffer.
	got[0] ^= 0xFF
	if resp[0] == got[0] {
		t.Fatalf("response aliases firmware buffer")
	}
}

func TestSendStatusErrors(t *testing.T) {
	// Each known EFI_ERROR code maps to its sentinel; an unknown one maps to
	// ErrStatus; a Caller transport error takes precedence over status.
	callErr := errors.New("trap")
	cases := []struct {
		name   string
		status uintptr
		err    error
		want   error
	}{
		{"invalid", statusErrorBit | codeInvalidParameter, nil, ErrInvalidParameter},
		{"buffer", statusErrorBit | codeBufferTooSmall, nil, ErrBufferTooSmall},
		{"device", statusErrorBit | codeDeviceError, nil, ErrDeviceError},
		{"notfound", statusErrorBit | codeNotFound, nil, ErrNotFound},
		{"other", statusErrorBit | 0x99, nil, ErrStatus},
		{"callErr", efiSuccess, callErr, callErr},
		{"callErrBeatsStatus", statusErrorBit | codeDeviceError, callErr, callErr},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeCaller{subStatus: c.status, subErr: c.err}
			_, err := New(f).Send([]byte("cmd"))
			if !errors.Is(err, c.want) {
				t.Fatalf("Send err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestSendShortResponse(t *testing.T) {
	// Firmware reports success but the output's responseSize is below the
	// 10-byte header. tpmResponse(8,...) leaves an 8-byte-declared response.
	short := tpmResponse(common.HeaderSize, 0)
	short[5] = common.HeaderSize - 1 // declare size 9 < HeaderSize
	f := &fakeCaller{subResp: short, subStatus: efiSuccess}
	if _, err := NewWithOutputSize(f, 64).Send([]byte("cmd")); !errors.Is(err, ErrShortResponse) {
		t.Fatalf("Send err = %v, want ErrShortResponse", err)
	}
}

func TestSendShortResponseUnreadableHeader(t *testing.T) {
	// Output buffer smaller than the header offset of responseSize so
	// common.GetU32 fails (the !ok branch of ErrShortResponse).
	f := &fakeCaller{subStatus: efiSuccess}
	if _, err := NewWithOutputSize(f, 4).Send([]byte("cmd")); !errors.Is(err, ErrShortResponse) {
		t.Fatalf("Send err = %v, want ErrShortResponse", err)
	}
}

func TestSendResponseTooLarge(t *testing.T) {
	// responseSize larger than the output buffer the firmware was given.
	resp := tpmResponse(40, 0)
	f := &fakeCaller{subResp: resp[:16], subStatus: efiSuccess}
	// Use a 16-byte output; header declares 40 > 16.
	if _, err := NewWithOutputSize(f, 16).Send([]byte("cmd")); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Send err = %v, want ErrResponseTooLarge", err)
	}
}

func TestMeasureToPCRLayout(t *testing.T) {
	f := &fakeCaller{hleStatus: efiSuccess}
	tpm := New(f)

	data := []byte{0x01, 0x02, 0x03, 0x04}
	desc := []byte("kernel") // 6 bytes
	if err := tpm.MeasureToPCR(8, 0x80000007, data, desc); err != nil {
		t.Fatalf("MeasureToPCR err = %v", err)
	}

	// dataToHash is forwarded verbatim.
	if !bytes.Equal(f.hleData, data) {
		t.Fatalf("dataToHash = %x, want %x", f.hleData, data)
	}
	// FlagNone by default.
	if f.hleFlags != FlagNone {
		t.Fatalf("flags = %#x, want FlagNone", f.hleFlags)
	}

	// Hand-derived EFI_TCG2_EVENT (little-endian, packed):
	//   Size            = 18 + 6 = 24       -> 18 00 00 00
	//   HeaderSize      = 14                 -> 0e 00 00 00
	//   HeaderVersion   = 1                  -> 01 00
	//   PCRIndex        = 8                  -> 08 00 00 00
	//   EventType       = 0x80000007         -> 07 00 00 80
	//   Event[]         = "kernel"           -> 6b 65 72 6e 65 6c
	want := []byte{
		0x18, 0x00, 0x00, 0x00,
		0x0e, 0x00, 0x00, 0x00,
		0x01, 0x00,
		0x08, 0x00, 0x00, 0x00,
		0x07, 0x00, 0x00, 0x80,
		0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c,
	}
	if !bytes.Equal(f.hleEvent, want) {
		t.Fatalf("EFI_TCG2_EVENT =\n %x\nwant\n %x", f.hleEvent, want)
	}
	// The leading Size field equals the buffer's own length.
	if int(want[0]) != len(f.hleEvent) {
		t.Fatalf("Size field %d != event len %d", want[0], len(f.hleEvent))
	}
}

func TestMeasureToPCREmptyDesc(t *testing.T) {
	// Zero-length event description: Size = 18, no Event[] bytes.
	f := &fakeCaller{hleStatus: efiSuccess}
	if err := New(f).MeasureToPCR(0, 0, nil, nil); err != nil {
		t.Fatalf("MeasureToPCR err = %v", err)
	}
	if len(f.hleEvent) != eventOverhead {
		t.Fatalf("event len = %d, want %d", len(f.hleEvent), eventOverhead)
	}
	if f.hleEvent[0] != eventOverhead {
		t.Fatalf("Size = %d, want %d", f.hleEvent[0], eventOverhead)
	}
}

func TestMeasureToPCRWithFlags(t *testing.T) {
	f := &fakeCaller{hleStatus: efiSuccess}
	if err := New(f).MeasureToPCRWithFlags(FlagPECOFFImage, 4, 0xEF, []byte("x"), []byte("y")); err != nil {
		t.Fatalf("MeasureToPCRWithFlags err = %v", err)
	}
	if f.hleFlags != FlagPECOFFImage {
		t.Fatalf("flags = %#x, want FlagPECOFFImage", f.hleFlags)
	}
}

func TestMeasureToPCRError(t *testing.T) {
	// Every status branch is already covered by Send; confirm MeasureToPCR
	// routes through statusError too, including a Caller transport error.
	f := &fakeCaller{hleStatus: statusErrorBit | codeDeviceError}
	if err := New(f).MeasureToPCR(8, 0, nil, nil); !errors.Is(err, ErrDeviceError) {
		t.Fatalf("err = %v, want ErrDeviceError", err)
	}
	callErr := errors.New("hle trap")
	f2 := &fakeCaller{hleErr: callErr}
	if err := New(f2).MeasureToPCR(8, 0, nil, nil); !errors.Is(err, callErr) {
		t.Fatalf("err = %v, want callErr", err)
	}
}

func TestStatusErrorBitWidth(t *testing.T) {
	// statusErrorBit must be the single top bit of a machine word: exactly
	// one bit set, and clearing it from an all-ones word leaves the low half.
	if statusErrorBit&(statusErrorBit-1) != 0 {
		t.Fatalf("statusErrorBit has more than one bit set: %#x", statusErrorBit)
	}
	if statusErrorBit == 0 {
		t.Fatalf("statusErrorBit is zero")
	}
	if (^uintptr(0))&^statusErrorBit != ^uintptr(0)>>1 {
		t.Fatalf("statusErrorBit is not the most-significant bit")
	}
}

// TestTransportSatisfied is a compile-and-run check that *TCG2 is usable
// where a common.Transport is expected.
func TestTransportSatisfied(t *testing.T) {
	resp := tpmResponse(12, 0)
	f := &fakeCaller{subResp: resp, subStatus: efiSuccess}
	var tr common.Transport = NewWithOutputSize(f, 32)
	if _, err := tr.Send([]byte("cmd")); err != nil {
		t.Fatalf("Send via common.Transport err = %v", err)
	}
}
