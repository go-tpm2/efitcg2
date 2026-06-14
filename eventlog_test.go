// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/efitcg2 authors. All rights reserved.

package efitcg2

import (
	"bytes"
	"errors"
	"testing"
)

// eventLogCaller is a fakeCaller that also implements EventLogCaller, recording
// the requested format and returning a canned (log, truncated, err) result.
type eventLogCaller struct {
	fakeCaller
	gotFormat uint32
	log       []byte
	truncated bool
	logErr    error
}

func (e *eventLogCaller) GetEventLog(format uint32) ([]byte, bool, error) {
	e.gotFormat = format
	return e.log, e.truncated, e.logErr
}

// cannedCryptoAgileLog returns a minimal well-formed crypto-agile TCG event log:
// a legacy TCG_PCR_EVENT spec-ID header declaring the SHA-256 bank, followed by a
// single TCG_PCR_EVENT2. It is shaped exactly like attest's LogBuilder output so
// the integration assertion (this log parses) is meaningful, but is built here
// by hand to keep efitcg2 dependency-free of attest.
func cannedCryptoAgileLog() []byte {
	// --- TCG_EfiSpecIdEvent body (the Event[] of the legacy header). ---
	var spec []byte
	spec = append(spec, []byte("Spec ID Event03\x00")...) // 16-byte signature
	spec = appendBE32(spec, 0)                            // platformClass
	spec = append(spec, 0)                                // specVersionMinor
	spec = append(spec, 2)                                // specVersionMajor (TPM 2.0)
	spec = append(spec, 0)                                // specErrata
	spec = append(spec, 2)                                // uintnSize (8-byte UINTN)
	spec = appendBE32(spec, 1)                            // numberOfAlgorithms
	spec = appendBE16(spec, 0x000B)                       // algId = TPM_ALG_SHA256
	spec = appendBE16(spec, 32)                           // digestSize
	spec = append(spec, 0)                                // vendorInfoSize

	// --- Legacy TCG_PCR_EVENT wrapping the spec-ID event. ---
	var out []byte
	out = appendBE32(out, 0)                 // PCRIndex
	out = appendBE32(out, 0x00000003)        // EventType = EV_NO_ACTION
	out = append(out, make([]byte, 20)...)   // SHA-1 digest (zero)
	out = appendBE32(out, uint32(len(spec))) // EventSize
	out = append(out, spec...)               // Event[] = spec-ID event

	// --- One TCG_PCR_EVENT2 (crypto-agile). ---
	out = appendBE32(out, 4)                             // PCRIndex = 4
	out = appendBE32(out, 0x80000003)                    // EventType = EV_EFI_BOOT_SERVICES_APPLICATION
	out = appendBE32(out, 1)                             // Digests.count
	out = appendBE16(out, 0x000B)                        // algId = SHA-256
	out = append(out, bytes.Repeat([]byte{0xAB}, 32)...) // 32-byte digest
	data := []byte("vmlinuz")
	out = appendBE32(out, uint32(len(data))) // EventSize
	out = append(out, data...)               // Event[]
	return out
}

func appendBE16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendBE32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func TestEventLogFormatConstants(t *testing.T) {
	if EventLogFormatTCG_1_2 != 0x00000001 {
		t.Fatalf("EventLogFormatTCG_1_2 = %#x, want 0x1", EventLogFormatTCG_1_2)
	}
	if EventLogFormatTCG_2 != 0x00000002 {
		t.Fatalf("EventLogFormatTCG_2 = %#x, want 0x2", EventLogFormatTCG_2)
	}
	// GetEventLog is vtable index 1.
	if MethodGetEventLog != 1 {
		t.Fatalf("MethodGetEventLog = %d, want 1", MethodGetEventLog)
	}
}

func TestGetEventLogSuccess(t *testing.T) {
	log := cannedCryptoAgileLog()
	e := &eventLogCaller{log: log}
	got, err := New(e).GetEventLog()
	if err != nil {
		t.Fatalf("GetEventLog err = %v", err)
	}
	if !bytes.Equal(got, log) {
		t.Fatalf("GetEventLog bytes = %x, want %x", got, log)
	}
	// The crypto-agile format (0x2) was requested, not the legacy 1.2 format.
	if e.gotFormat != EventLogFormatTCG_2 {
		t.Fatalf("requested format = %#x, want EventLogFormatTCG_2", e.gotFormat)
	}
}

func TestGetEventLogUnsupported(t *testing.T) {
	// A plain Caller (no EventLogCaller): GetEventLog never asks the firmware.
	f := &fakeCaller{}
	got, err := New(f).GetEventLog()
	if !errors.Is(err, ErrEventLogUnsupported) {
		t.Fatalf("GetEventLog err = %v, want ErrEventLogUnsupported", err)
	}
	if got != nil {
		t.Fatalf("GetEventLog bytes = %x, want nil", got)
	}
}

func TestGetEventLogTruncated(t *testing.T) {
	// Firmware sets EventLogTruncated: bytes are surfaced ALONGSIDE the warning.
	log := cannedCryptoAgileLog()
	e := &eventLogCaller{log: log, truncated: true}
	got, err := New(e).GetEventLog()
	if !errors.Is(err, ErrEventLogTruncated) {
		t.Fatalf("GetEventLog err = %v, want ErrEventLogTruncated", err)
	}
	if !bytes.Equal(got, log) {
		t.Fatalf("truncated GetEventLog bytes = %x, want the (partial) log %x", got, log)
	}
}

func TestGetEventLogCallerError(t *testing.T) {
	// A Caller call/read error is returned with nil bytes (no usable log).
	callErr := errors.New("firmware-memory read trap")
	e := &eventLogCaller{log: cannedCryptoAgileLog(), logErr: callErr}
	got, err := New(e).GetEventLog()
	if !errors.Is(err, callErr) {
		t.Fatalf("GetEventLog err = %v, want callErr", err)
	}
	if got != nil {
		t.Fatalf("GetEventLog bytes = %x, want nil on error", got)
	}
}

func TestGetEventLogEmpty(t *testing.T) {
	// An empty log (no measurements) is a valid nil-bytes, nil-err result.
	e := &eventLogCaller{log: nil}
	got, err := New(e).GetEventLog()
	if err != nil {
		t.Fatalf("GetEventLog err = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("GetEventLog bytes = %x, want nil", got)
	}
}
