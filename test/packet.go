package test

import (

	// "github.com/free5gc/openapi/models"

	"encoding/binary"
	"fmt"
	"net"
	"test/ngapTestpacket"

	"github.com/free5gc/aper"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/ngap"
)

// This function is used for nas packet
func DecodePDUSessionEstablishmentAccept(ue *RanUeContext, length int, buffer []byte) (
	*message.PDUSessEstAccept, error,
) {
	if length == 0 {
		return nil, fmt.Errorf("Empty buffer")
	}

	nasEnv, n, err := DecapNasPduFromEnvelope(buffer[:length])
	if err != nil {
		return nil, err
	}

	nasMsg, err := NASDecode(ue, message.SecHdrTypeIntegrityProtectedAndCiphered, nasEnv[:n])
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}

	// The GSM message travels inside the DL NAS transport payload container and
	// has to be parsed separately.
	dlTransport, ok := nasMsg.(*message.DLNASTransport)
	if !ok {
		return nil, fmt.Errorf("expected DLNASTransport, got %T", nasMsg)
	}
	if dlTransport.PayloadCntr == nil {
		return nil, fmt.Errorf("DLNASTransport has no payload container")
	}

	gsmMsg, err := message.ParseGSM(dlTransport.PayloadCntr.Contents)
	if err != nil {
		return nil, fmt.Errorf("NAS Decode Fail: %+v", err)
	}
	accept, ok := gsmMsg.(*message.PDUSessEstAccept)
	if !ok {
		return nil, fmt.Errorf("expected PDUSessEstAccept, got %T", gsmMsg)
	}

	return accept, nil
}

// This function is used for nas packet
func GetPDUAddress(accept *message.PDUSessEstAccept) (net.IP, error) {
	if accept == nil {
		return nil, fmt.Errorf("PDUSessEstAccept is nil")
	} else if addr := accept.PDUAddr; addr != nil {
		if accept.SelectedPDUSessType != nil &&
			accept.SelectedPDUSessType.Value == ie.PDUSessType_IPv4 {
			return net.IP(addr.IPv4), nil
		}
	}

	return nil, fmt.Errorf("PDUAddress is nil")
}

func GetNGSetupRequest(gnbId []byte, bitlength uint64, name string, tac string, sst string, sd string) ([]byte, error) {
	message := ngapTestpacket.BuildNGSetupRequest()
	// GlobalRANNodeID
	ie := message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[0]
	gnbID := ie.Value.GlobalRANNodeID.GlobalGNBID.GNBID.GNBID
	gnbID.Bytes = gnbId
	gnbID.BitLength = bitlength
	// RANNodeName
	ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[1]
	ie.Value.RANNodeName.Value = name
	if tac != "" {
		ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[2]
		ie.Value.SupportedTAList.List[0].TAC.Value = aper.OctetString(tac)
	}
	if sst != "" {
		ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[2]
		ie.Value.SupportedTAList.List[0].BroadcastPLMNList.List[0].TAISliceSupportList.List[0].SNSSAI.SST.Value = aper.OctetString(sst)
	}
	if sd != "" {
		ie = message.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List[2]
		ie.Value.SupportedTAList.List[0].BroadcastPLMNList.List[0].TAISliceSupportList.List[0].SNSSAI.SD.Value = aper.OctetString(sd)
	}

	return ngap.Encoder(message)
}

func GetInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) ([]byte, error) {
	message := ngapTestpacket.BuildInitialUEMessage(ranUeNgapID, nasPdu, fiveGSTmsi)
	return ngap.Encoder(message)
}

func GetUplinkNASTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ([]byte, error) {
	message := ngapTestpacket.BuildUplinkNasTransport(amfUeNgapID, ranUeNgapID, nasPdu)
	return ngap.Encoder(message)
}

func GetInitialContextSetupResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := ngapTestpacket.BuildInitialContextSetupResponseForRegistraionTest(amfUeNgapID, ranUeNgapID)

	return ngap.Encoder(message)
}

func GetInitialContextSetupResponseForServiceRequest(
	amfUeNgapID int64, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	message := ngapTestpacket.BuildInitialContextSetupResponse(amfUeNgapID, ranUeNgapID, ipv4, nil)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceSetupResponse(pduSessionId int64, amfUeNgapID int64, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	message := ngapTestpacket.BuildPDUSessionResourceSetupResponseForRegistrationTest(pduSessionId, amfUeNgapID, ranUeNgapID, ipv4)
	return ngap.Encoder(message)
}

// EncodeNasPduWithSecurity takes an already-built plain NAS PDU and wraps it in
// a security envelope. The new API works on message.Message rather than raw
// bytes, so the PDU is parsed back first; that round trip is byte-exact for
// every message nasTestpacket produces (covered by its own tests).
func EncodeNasPduWithSecurity(ue *RanUeContext, pdu []byte, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m, err := message.ParseGMM(pdu)
	if err != nil {
		return nil, err
	}
	return NASEncode(ue, m, securityHeaderType, securityContextAvailable, newSecurityContext)
}

func EncodeNasPduInEnvelopeWithSecurity(ue *RanUeContext, pdu []byte, securityHeaderType message.SecHdrType,
	securityContextAvailable, newSecurityContext bool,
) ([]byte, error) {
	m, err := message.ParseGMM(pdu)
	if err != nil {
		return nil, err
	}
	return NASEnvelopeEncode(ue, m, securityHeaderType, securityContextAvailable, newSecurityContext)
}

func DecapNasPduFromEnvelope(envelop []byte) ([]byte, int, error) {
	// According to TS 24.502 8.2.4 and TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	if uint16(len(envelop)) < 2 {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than 2 bytes")
	}
	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	if uint16(len(envelop)) < 2+nasLen {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than the sum of 2 and naslen")
	}
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg, int(nasLen), nil
}

func GetUEContextReleaseComplete(amfUeNgapID int64, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	message := ngapTestpacket.BuildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID, pduSessionIDList)
	return ngap.Encoder(message)
}

func GetUEContextReleaseRequest(amfUeNgapID int64, ranUeNgapID int64, pduSessionIDList []int64) ([]byte, error) {
	message := ngapTestpacket.BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID, pduSessionIDList)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceReleaseResponse(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := ngapTestpacket.BuildPDUSessionResourceReleaseResponseForReleaseTest(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}
func GetPathSwitchRequest(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := ngapTestpacket.BuildPathSwitchRequest(amfUeNgapID, ranUeNgapID)
	message.InitiatingMessage.Value.PathSwitchRequest.ProtocolIEs.List =
		message.InitiatingMessage.Value.PathSwitchRequest.ProtocolIEs.List[0:5]
	return ngap.Encoder(message)
}

func GetHandoverRequired(
	amfUeNgapID int64, ranUeNgapID int64, targetGNBID []byte, targetCellID []byte) ([]byte, error) {
	message := ngapTestpacket.BuildHandoverRequired(amfUeNgapID, ranUeNgapID, targetGNBID, targetCellID)
	return ngap.Encoder(message)
}

func GetHandoverRequestAcknowledge(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := ngapTestpacket.BuildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}

func GetHandoverNotify(amfUeNgapID int64, ranUeNgapID int64) ([]byte, error) {
	message := ngapTestpacket.BuildHandoverNotify(amfUeNgapID, ranUeNgapID)
	return ngap.Encoder(message)
}

func GetPDUSessionResourceSetupResponseForPaging(amfUeNgapID int64, ranUeNgapID int64, ipv4 string) ([]byte, error) {
	message := ngapTestpacket.BuildPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID, ipv4)
	return ngap.Encoder(message)
}
