// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// decodeValue decodes the body of the block types that keep it in Value
// and Blocks. A decoder returns nil for a version it does not know and for
// a body shorter than its fixed fields.
func (b *ProfinetBlock) decodeValue(r *profinetReader) {
	low := b.VersionLow

	switch {
	case b.Type == ProfinetBlockDiagnosisData:
		b.Value = decodeProfinetDiagnosis(r, low)
	case b.Type >= profinetBlockIdentFirst && b.Type <= profinetBlockIdentLast:
		b.Value = b.decodeIdentValue(r, low)
	case b.Type >= profinetBlockMrpFirst && b.Type <= profinetBlockMrpLast,
		b.Type >= ProfinetBlockMrpInstAdjust && b.Type <= ProfinetBlockMrpInstCheck:
		b.Value = b.decodeMrpValue(r, low)
	case b.Type >= ProfinetBlockRSAdjustObserver && b.Type <= ProfinetBlockRSAckEvent:
		b.Value = b.decodeRSValue(r, low)
	case b.Type >= ProfinetBlockCIMPortConfig && b.Type <= ProfinetBlockRecordPolicyReal:
		b.Value = b.decodeTSNValue(r, low)
	}
	if b.Decoded() {
		return
	}

	// The remaining groups share no range.
	if b.Value = b.decodePDValue(r, low); b.Decoded() {
		return
	}
	if b.Value = b.decodeARValue(r, low); b.Decoded() {
		return
	}
	b.Value = b.decodeSecValue(r, low)
}

// Ranges of block types one decoder covers. Types inside a range that it
// does not know stay raw.
const (
	profinetBlockIdentFirst = ProfinetBlockExpectedIdent
	profinetBlockIdentLast  = ProfinetBlockAMFirmwareOnly
	profinetBlockMrpFirst   = ProfinetBlockPDIfMrpAdjust
	profinetBlockMrpLast    = ProfinetBlockMrpRTModeClient
)

// decodeIdentValue decodes the identification blocks of profinet_im.go.
func (b *ProfinetBlock) decodeIdentValue(r *profinetReader, low uint8) interface{} {
	// The identification data has two versions; everything else one.
	switch b.Type {
	case ProfinetBlockExpectedIdent, ProfinetBlockRealIdent:
		switch low {
		case 0:
			return decodeProfinetIdent(r, profinetIdentNoAPI)
		case profinetBlockVersionLowAPI:
			return decodeProfinetIdent(r, profinetIdentWithAPI)
		}
		return nil
	}
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockIM0:
		return decodeProfinetIM0(r)
	case ProfinetBlockIM1:
		return decodeProfinetIM1(r)
	case ProfinetBlockIM2:
		return decodeProfinetIM2(r)
	case ProfinetBlockIM3:
		return decodeProfinetIM3(r)
	case ProfinetBlockIM4:
		return decodeProfinetIM4(r)
	case ProfinetBlockIM5Data:
		return decodeProfinetIM5Data(r)
	case ProfinetBlockIM5, ProfinetBlockAssetManagement:
		return decodeProfinetEntries(r, b)
	case ProfinetBlockIM0FilterSubmod, ProfinetBlockIM0FilterModule, ProfinetBlockIM0FilterDevice:
		return decodeProfinetIdent(r, profinetIdentWithAPI)
	case ProfinetBlockAMFullInfo, ProfinetBlockAMHardwareOnly, ProfinetBlockAMFirmwareOnly:
		return decodeProfinetAssetInfo(r, b.Type)
	}
	return nil
}
