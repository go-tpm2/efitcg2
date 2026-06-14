// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026, the go-tpm2/efitcg2 authors. All rights reserved.

// This file adds the EFI_TCG2_PROTOCOL.GetEventLog surface to the transport:
// the ability to fetch the FIRMWARE-maintained TCG measured-boot event log so
// that github.com/go-tpm2/attest can ParseEventLog + ReplayPCRs it and confirm
// the replay matches the firmware's PCRs.
//
// Specification. The protocol member is defined by the TCG "EFI Protocol
// Specification, Family 2.0", clause "EFI_TCG2_PROTOCOL.GetEventLog()":
//
//	EFI_STATUS GetEventLog(
//	    IN  EFI_TCG2_PROTOCOL          *This,
//	    IN  EFI_TCG2_EVENT_LOG_FORMAT   EventLogFormat,
//	    OUT EFI_PHYSICAL_ADDRESS       *EventLogLocation,
//	    OUT EFI_PHYSICAL_ADDRESS       *EventLogLastEntry,
//	    OUT BOOLEAN                    *EventLogTruncated );
//
// It does NOT copy the log: it returns the firmware-memory ADDRESS of the log's
// first entry, the address of its LAST entry, and a truncation flag. Reading the
// bytes in [EventLogLocation, EventLogLastEntry + sizeof(last entry)) out of
// firmware memory therefore requires the loader's identity-mapped access — it is
// not something a UEFI/TamaGo-free package can do. Per this package's dependency
// discipline (see the package doc), that firmware-memory read lives in the
// INJECTED Caller, exactly like SubmitCommand/HashLogExtendEvent already do.
//
// efitcg2 only: (1) defines the format constants and the optional
// EventLogCaller extension a loader implements, (2) type-asserts the Caller to
// it (mirroring CapabilityCaller), and (3) returns the assembled bytes, which
// are then fed verbatim to attest.ParseEventLog. efitcg2 itself never touches
// firmware memory or a protocol pointer.

package efitcg2

import (
	"github.com/go-tpm2/common"
)

// EFI_TCG2_EVENT_LOG_FORMAT values, the EventLogFormat argument to
// EFI_TCG2_PROTOCOL.GetEventLog. TCG "EFI Protocol Specification",
// "EFI_TCG2_EVENT_LOG_FORMAT" (the EFI_TCG2_EVENT_LOG_FORMAT_TCG_*
// #defines).
const (
	// EventLogFormatTCG_1_2 is EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2 (0x1): the
	// legacy SHA-1-only TCG 1.2 log (TCG_PCR_EVENT records). Defined for
	// completeness; this stack does not parse it.
	EventLogFormatTCG_1_2 uint32 = 0x00000001
	// EventLogFormatTCG_2 is EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 (0x2): the
	// crypto-agile log (a legacy TCG_PCR_EVENT spec-ID header followed by
	// TCG_PCR_EVENT2 records). This is the format attest.ParseEventLog reads,
	// so it is the format GetEventLog requests.
	EventLogFormatTCG_2 uint32 = 0x00000002
)

// Event-log error/warning sentinels, typed as common.Error so callers may
// compare with ==.
const (
	// ErrEventLogUnsupported is returned by (*TCG2).GetEventLog when the injected
	// Caller does NOT implement the optional EventLogCaller extension, i.e. the
	// loader did not wire up firmware event-log retrieval. It is distinct from a
	// firmware EFI_STATUS error: the firmware was never asked.
	ErrEventLogUnsupported = common.Error("efitcg2: Caller does not implement EventLogCaller")
	// ErrEventLogTruncated is returned by (*TCG2).GetEventLog ALONGSIDE the log
	// bytes when the firmware set EFI_TCG2_PROTOCOL.GetEventLog's
	// EventLogTruncated out-parameter: the firmware's event-log area overflowed
	// and the returned bytes are incomplete. The bytes are still returned (a
	// truncated crypto-agile log may still parse up to the truncation point) so
	// the caller can decide; replaying a truncated log will not reproduce the
	// firmware PCRs, so attestation MUST treat this as a failure. Callers that
	// only want a complete log check errors.Is(err, ErrEventLogTruncated).
	ErrEventLogTruncated = common.Error("efitcg2: firmware reports the event log was truncated")
)

// EventLogCaller is an OPTIONAL extension a Caller may also implement to fetch
// the firmware-maintained TCG event log. It is queried via
// EFI_TCG2_PROTOCOL.GetEventLog (vtable index 1, see MethodGetEventLog).
//
// Why it lives in the Caller. GetEventLog returns firmware-memory ADDRESSES
// (EventLogLocation/EventLogLastEntry), not bytes; assembling the log means
// reading [location, lastEntry + sizeof(last entry)) out of firmware memory,
// which needs the loader's identity-mapped access and is outside efitcg2's
// UEFI/TamaGo-free remit. The loader therefore performs the whole firmware
// operation — call GetEventLog, take the out-params, parse the last
// TCG_PCR_EVENT2 header to size the final entry, read the exact byte range, and
// return the assembled bytes plus the firmware's EventLogTruncated flag.
//
// Contract. GetEventLog(format) requests the log in the given
// EFI_TCG2_EVENT_LOG_FORMAT and returns:
//   - log: the assembled event-log bytes in that format (a complete
//     crypto-agile log when format == EventLogFormatTCG_2: a legacy
//     TCG_PCR_EVENT spec-ID header followed by TCG_PCR_EVENT2 records). These
//     bytes are returned to efitcg2's caller unchanged and are intended to be
//     passed verbatim to attest.ParseEventLog. An empty log (no measurements
//     yet) is a valid (possibly nil/header-only) byte slice with a nil err.
//   - truncated: the firmware's EventLogTruncated out-parameter (the event-log
//     memory area overflowed). efitcg2 surfaces this as ErrEventLogTruncated.
//   - err: a failure to perform the firmware call or read its memory (a
//     marshaling/trap/transport problem on the loader side, or a non-success
//     EFI_STATUS the loader chose to map). A non-nil err means the log bytes
//     are not usable.
//
// TCG "EFI Protocol Specification", "EFI_TCG2_PROTOCOL.GetEventLog()" and
// "EFI_TCG2_EVENT_LOG_FORMAT".
type EventLogCaller interface {
	// GetEventLog fetches the firmware event log in the requested
	// EFI_TCG2_EVENT_LOG_FORMAT, returning the assembled bytes, the firmware's
	// truncation flag, and any call/read error.
	GetEventLog(format uint32) (log []byte, truncated bool, err error)
}

// GetEventLog fetches the FIRMWARE-maintained crypto-agile TCG event log
// (EFI_TCG2_EVENT_LOG_FORMAT_TCG_2) and returns its bytes, ready to be parsed by
// github.com/go-tpm2/attest's ParseEventLog and replayed with ReplayPCRs.
//
// It requires the injected Caller to implement the optional EventLogCaller
// extension (the loader-side firmware-memory read). When the Caller does NOT
// implement it, GetEventLog returns (nil, ErrEventLogUnsupported) — the firmware
// is never asked. When the firmware reports the log was truncated, GetEventLog
// returns the (incomplete) bytes ALONGSIDE ErrEventLogTruncated, so a caller can
// distinguish "no log" from "partial log": a truncated log will not replay to
// the firmware PCRs and MUST be rejected for attestation, but the bytes are
// surfaced rather than dropped. Any Caller call/read error is returned with nil
// bytes.
//
// The returned format is always EventLogFormatTCG_2 — the crypto-agile log
// attest parses; the legacy EventLogFormatTCG_1_2 (SHA-1 only) is not requested.
//
// TCG "EFI Protocol Specification", "EFI_TCG2_PROTOCOL.GetEventLog()"; TCG "PC
// Client Platform Firmware Profile", "Event Logging" (the crypto-agile log
// layout attest replays).
func (t *TCG2) GetEventLog() ([]byte, error) {
	elc, ok := t.c.(EventLogCaller)
	if !ok {
		return nil, ErrEventLogUnsupported
	}
	log, truncated, err := elc.GetEventLog(EventLogFormatTCG_2)
	if err != nil {
		return nil, err
	}
	if truncated {
		// Surface the bytes AND the warning: the log is incomplete (will not
		// replay to the firmware PCRs) but the caller may still want to inspect
		// it. attestation paths reject on errors.Is(err, ErrEventLogTruncated).
		return log, ErrEventLogTruncated
	}
	return log, nil
}
