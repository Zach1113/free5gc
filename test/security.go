package test

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/free5gc/nas/message"
)

func encapNasMsgToEnvelope(nasPDU []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU)))
	nasEnv = append(nasEnv, nasPDU...)
	return nasEnv
}

// NewSecCtx builds the security context the new nas API needs, borrowing the
// UE's own counters rather than copying them: message.Marshal and message.Parse
// advance the counter they are given, and that state has to stay in the
// RanUeContext for the rest of the flow. Anything derived from the UE (keys,
// algorithms, bearer) is read at call time, so this is safe to build fresh for
// every message -- and it has to be, because the keys only exist after
// DerivateAlgKey has run.
func (ue *RanUeContext) NewSecCtx() *message.SecCtx {
	secCtx := message.NewSecCtx(
		message.UESide,
		ue.GetBearerType(),
		ue.CipheringAlg,
		ue.IntegrityAlg,
		ue.KnasEnc[:],
		ue.KnasInt[:],
	)
	secCtx.UplinkCount = &ue.ULCount
	secCtx.DownlinkCount = &ue.DLCount
	return secCtx
}

// NASEncode serializes a NAS message, applying security when a context is
// available. The security header type used to be carried on nas.Message; the
// new API takes it as an explicit argument to message.Marshal.
func NASEncode(ue *RanUeContext, msg message.Message, securityHeaderType message.SecHdrType,
	securityContextAvailable bool, newSecurityContext bool,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ue is nil")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Message is empty")
	}

	if !securityContextAvailable {
		return message.Marshal(msg, nil, message.SecHdrTypePlainNas)
	}

	if newSecurityContext {
		// message.Marshal only resets the direction it is about to use, so
		// reset both here to keep the previous behaviour.
		ue.ULCount.Set(0, 0)
		ue.DLCount.Set(0, 0)
	}

	return message.Marshal(msg, ue.NewSecCtx(), securityHeaderType)
}

// NASEnvelopeEncode is NASEncode wrapped in the TS 24.502 9.4 envelope used
// over non-3GPP access.
func NASEnvelopeEncode(ue *RanUeContext, msg message.Message, securityHeaderType message.SecHdrType,
	securityContextAvailable bool, newSecurityContext bool,
) ([]byte, error) {
	payload, err := NASEncode(ue, msg, securityHeaderType, securityContextAvailable, newSecurityContext)
	if err != nil {
		return nil, err
	}
	return encapNasMsgToEnvelope(payload), nil
}

// NASDecode parses a received NAS message, verifying and decrypting it when the
// UE has a security context.
//
// message.Parse reports a MAC mismatch by returning both the parsed message and
// a *message.Error, and it rolls the counter back itself. The previous
// implementation only logged the mismatch and carried on, so keep that: the E2E
// tests exercise flows where the MAC is not expected to match yet.
func NASDecode(ue *RanUeContext, securityHeaderType message.SecHdrType, payload []byte) (message.Message, error) {
	if ue == nil {
		return nil, fmt.Errorf("ue is nil")
	}
	if payload == nil {
		return nil, fmt.Errorf("Nas payload is empty")
	}

	if securityHeaderType == message.SecHdrTypePlainNas {
		return message.Parse(payload, nil)
	}

	msg, err := message.Parse(payload, ue.NewSecCtx())

	var nasErr *message.Error
	if errors.As(err, &nasErr) && nasErr.MACFailure != nil {
		fmt.Printf("NAS MAC verification failed(0x%x != 0x%x)\n",
			nasErr.MACFailure.Expected, nasErr.MACFailure.Received)
		return msg, nil
	}

	return msg, err
}
