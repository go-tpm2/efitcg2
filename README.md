# go-tpm2/efitcg2

[![CI](https://github.com/go-tpm2/efitcg2/actions/workflows/ci.yml/badge.svg)](https://github.com/go-tpm2/efitcg2/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-tpm2/efitcg2.svg)](https://pkg.go.dev/github.com/go-tpm2/efitcg2)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](#conventions)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

A pure-Go TPM 2.0 transport backed by the UEFI **`EFI_TCG2_PROTOCOL`**. **v0.1.1.**

> Firmware-validated: the cloud-boot loader extends PCR4 through this transport's
> `MeasureToPCR` (`HashLogExtendEvent`) on real x86 OVMF firmware (Fedora
> `OVMF.stateless.fd` + `tpm-crb` + swtpm), confirmed in the firmware DEBUG log.
> v0.1.1 fixes the `SubmitCommand` output block to respect the firmware's
> `MaxResponseSize` (the CRB ceiling is 3968 = `0x1000−0x80`, not 4096) — found
> by that real-firmware run.

`efitcg2` implements
[`github.com/go-tpm2/common`](https://github.com/go-tpm2/common)'s `Transport`
so that go-tpm2's command layer (Quote, GetCapability, seal/unseal, …) can
drive a **firmware** TPM while the machine is still in **Boot Services** —
for example a TamaGo + UEFI loader running under OVMF, where the TPM is owned
by firmware and raw TIS/CRB MMIO is the wrong interface.

The protocol is the TCG **EFI Protocol Specification, Family 2.0**, clause
*`EFI_TCG2_PROTOCOL`* (surfaced in the UEFI specification).

## Why not TIS/CRB here?

Under a pre-`ExitBootServices` loader the firmware already owns the TPM:
localities, active PCR banks, and the TCG event log are established, and
firmware is still servicing the device. `EFI_TCG2_PROTOCOL.SubmitCommand` is
the supported path for a marshaled TPM 2.0 command, and
`HashLogExtendEvent` is the supported measured-boot primitive (it extends a
PCR **and** appends an event-log record in one firmware call). Poking TIS/CRB
registers directly at that point races firmware and is incorrect.

## Dependency discipline

**go-tpm2 stays UEFI/TamaGo-dependency-free.** This package never imports an
EFI runtime, never dereferences a protocol pointer, and never uses package
`unsafe`. It takes an **injected** firmware-call mechanism — a `Caller` the
loader implements — exactly the way `go-tpm2/tis` and `go-tpm2/crb` take an
injected `common.Regs`. The loader owns the protocol pointer and the EFI
calling convention; `efitcg2` only marshals buffers and interprets results.

## The injected-`Caller` contract (this is what the loader implements)

```go
// Caller is the entire UEFI-facing surface of efitcg2. The loader holds the
// EFI_TCG2_PROTOCOL pointer + the platform efiCall and performs the actual
// firmware invocation; efitcg2 hands it marshaled buffers and reads the
// returned EFI_STATUS. A non-nil err reports a failure to perform the call
// itself (distinct from a non-success status); when err is nil, status
// alone decides success.
type Caller interface {
    // EFI_TCG2_PROTOCOL.SubmitCommand(This, len(inputBlock), inputBlock,
    //                                 len(output), output)
    // Firmware writes the TPM response into output in place.
    SubmitCommand(inputBlock []byte, output []byte) (status uintptr, err error)

    // EFI_TCG2_PROTOCOL.HashLogExtendEvent(This, flags, dataToHash,
    //                                      len(dataToHash), event)
    // event is the serialized EFI_TCG2_EVENT (its leading Size states its
    // own length).
    HashLogExtendEvent(flags uint64, dataToHash []byte, event []byte) (status uintptr, err error)
}
```

`status` is the raw `EFI_STATUS` as a `uintptr`, so the platform's native
word width carries the high "error" bit unchanged. `efitcg2` maps it:
`EFI_SUCCESS → nil`, and `EFI_INVALID_PARAMETER` / `EFI_BUFFER_TOO_SMALL` /
`EFI_DEVICE_ERROR` / `EFI_NOT_FOUND` / any-other-error to typed sentinels.

A loader that prefers a single low-level dispatcher may implement `Caller`
over a `Call(method int, args ...uintptr) uintptr` closure using the exported
`Method*` ordinals (`MethodGetCapability` … `MethodGetResultOfSetActivePcrBanks`,
declaration order) — that is invisible to `efitcg2`.

## Loader-side integration sketch (cloud-boot)

```go
import (
    "github.com/go-tpm2/common"
    "github.com/go-tpm2/efitcg2"
    // loader's own UEFI bindings — NOT imported by efitcg2/go-tpm2:
    "example.com/cloudboot/uefi"
)

// 1. Locate the protocol once, early in Boot Services.
var tcg2 *uefi.Protocol
err := bootServices.LocateProtocol(efitcg2.TCG2ProtocolGUID, nil, &tcg2)

// 2. Implement Caller over the located pointer + the platform efiCall.
type fwCaller struct{ p *uefi.Protocol }

func (f fwCaller) SubmitCommand(in, out []byte) (uintptr, error) {
    // efiCall(f.p.SubmitCommand, This, inLen, &in[0], outLen, &out[0])
    return uefi.Call(f.p.SubmitCommand,
        uintptr(unsafe.Pointer(f.p)),
        uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])),
        uintptr(len(out)), uintptr(unsafe.Pointer(&out[0]))), nil
}
func (f fwCaller) HashLogExtendEvent(flags uint64, data, event []byte) (uintptr, error) {
    return uefi.Call(f.p.HashLogExtendEvent,
        uintptr(unsafe.Pointer(f.p)), uintptr(flags),
        uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
        uintptr(unsafe.Pointer(&event[0]))), nil
}

// 3. Wrap it as a common.Transport and hand it to go-tpm2.
tpm := efitcg2.New(fwCaller{p: tcg2})    // *efitcg2.TCG2 satisfies common.Transport
rsp, err := tpm.Send(cmd)                // any tpm2 command works over EFI_TCG2

// 4. Measured boot: extend a PCR AND append a TCG event-log record.
err = tpm.MeasureToPCR(8, eventType, imageBytes, []byte("kernel"))
```

(The `unsafe`/`efiCall` lives in the **loader**, never in `efitcg2`.)

## API

- `New(c Caller) *TCG2` / `NewWithOutputSize(c, n)` — bind the transport;
  the output buffer defaults to `DefaultOutputSize` (4096).
- `(*TCG2) Send(cmd []byte) ([]byte, error)` — `common.Transport`. Calls
  `SubmitCommand` with `cmd` as the `InputParameterBlock`, parses the 10-byte
  TPM response header (`common.GetU32` of `responseSize`), bounds-checks it,
  and returns the response trimmed to that size.
- `(*TCG2) MeasureToPCR(pcr, eventType uint32, data, eventDesc []byte) error`
  / `MeasureToPCRWithFlags(flags, …)` — build an `EFI_TCG2_EVENT` and call
  `HashLogExtendEvent`.
- `TCG2ProtocolGUID` (`607f766c-7455-42be-930b-e4d76db2720f`) — pass to
  `LocateProtocol`.

## `EFI_TCG2_EVENT` layout emitted by `MeasureToPCR`

Little-endian, packed, 1-byte aligned (UEFI `#pragma pack(1)`), **unlike**
the big-endian TPM 2.0 wire stream `Send` carries. TCG "EFI Protocol
Specification", `EFI_TCG2_EVENT` / `EFI_TCG2_EVENT_HEADER`:

```
offset size field
  0     u32  Size                 = 18 + len(eventDesc)   (total)
  4     u32  Header.HeaderSize    = 14
  8     u16  Header.HeaderVersion = 1
 10     u32  Header.PCRIndex      = pcr
 14     u32  Header.EventType     = eventType
 18     ...  Event[]              = eventDesc
```

## INFERRED items (confirm under OVMF)

The spec fixes the method **order**, GUID, struct **fields**, flags, and
`EFI_STATUS` codes; the EFI **ABI** details are platform-dependent and marked
`// INFERRED:` in the source for the OVMF validation:

- **Vtable byte offsets** — `Method*` ordinals map to `ordinal*sizeof(void*)`
  only if firmware packs the protocol struct with no inter-member padding.
  `efitcg2` itself never indexes the vtable (it has no protocol pointer); only
  a `Call`-style loader does.
- **`EFI_TCG2_EVENT` packing/alignment** — assumed `#pragma pack(1)`,
  little-endian, no padding. Byte-asserted in tests against a hand-derived
  buffer; OVMF confirms firmware accepts it.
- **`DefaultOutputSize = 4096`** — assumed sufficient for every firmware-TPM
  response over `SubmitCommand`; a too-small block surfaces as
  `ErrBufferTooSmall` (observable, never silent).

End-to-end validation requires a UEFI/OVMF guest exposing `EFI_TCG2`
(the cloud-boot integration step). The unit tests here use a **fake**
firmware Caller; **no real-firmware pass is claimed**.

## Conventions

Pure Go, `CGO_ENABLED=0`, no assembly, BSD-3-Clause, 100% statement coverage
(`GOWORK=off go test -cover`). Spec citations are inline; ABI-dependent values
are marked `// INFERRED:`.
