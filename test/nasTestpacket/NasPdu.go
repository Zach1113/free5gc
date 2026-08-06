// Package nasTestpacket builds the UE-side (uplink) NAS messages used by the
// E2E test suite. Migrated to the new github.com/free5gc/nas API: messages are
// plain structs in nas/message with typed IEs from nas/ie, and are serialized
// with MarshalBinary instead of nas.NewMessage + GmmMessageEncode/GsmMessageEncode.
package nasTestpacket

import (
	"encoding/base64"
	"fmt"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

const (
	PDUSesModiReq    string = "PDU Session Modification Request"
	PDUSesModiCmp    string = "PDU Session Modification Complete"
	PDUSesModiCmdRej string = "PDU Session Modification Command Reject"
	PDUSesRelReq     string = "PDU Session Release Request"
	PDUSesRelCmp     string = "PDU Session Release Complete"
	PDUSesRelRej     string = "PDU Session Release Reject"
	PDUSesAuthCmp    string = "PDU Session Authentication Complete"
)

// marshal serializes a NAS message, preserving the previous behaviour of
// printing the error and returning whatever was produced.
func marshal(m interface{ MarshalBinary() ([]byte, error) }) []byte {
	b, err := m.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	return b
}

// newULNASTransport builds the common ULNASTransport envelope carrying an N1 SM
// payload. Every GetUlNasTransport_* helper differs only in which optional IEs
// it sets, so they all funnel through here.
func newULNASTransport(pduSessionId uint8, payload []byte) *message.ULNASTransport {
	return &message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Contents: payload},
		PDUSessID:       &ie.PDUSessId2{Value: pduSessionId},
	}
}

// setULNASTransportRouting fills the IEs the AMF needs to route an N1 SM
// payload to the right SMF: request type, DNN and S-NSSAI.
func setULNASTransportRouting(m *message.ULNASTransport, requestType uint8, dnnString string, sNssai *models.Snssai) {
	m.ReqType = &ie.ReqType{Value: ie.ConstReqType(requestType)}
	if dnnString != "" {
		m.DNN = &ie.DNN{Value: dnnString}
	}
	if sNssai != nil {
		// SD is a hex string in the new API; no manual decoding needed.
		m.SNSSAI = &ie.SNSSAI{
			SST: uint8(sNssai.Sst),
			SD:  sNssai.Sd,
		}
	}
}

func GetRegistrationRequest(
	registrationType uint8,
	mobileIdentity *ie.MobileId5GS,
	requestedNSSAI *ie.NSSAI,
	ueSecurityCapability *ie.UESecCapability,
	capability5GMM *ie.Capability5GMM,
	nasMessageContainer []uint8,
	uplinkDataStatus *ie.UplinkDataStatus,
) []byte {
	m := &message.RegReq{
		RegType5GS: &ie.RegType5GS{
			FOR_Pending: true,
			Value:       registrationType,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxTypeNative,
			Ksi: 0x7,
		},
		MobileId5GS:     mobileIdentity,
		UESecCapability: ueSecurityCapability,
		Capability5GMM:  capability5GMM,
		ReqNSSAI:        requestedNSSAI,
		UplinkDataStatus: uplinkDataStatus,
	}

	if nasMessageContainer != nil {
		m.NASMsgCntr = &ie.NASMsgCntr{Contents: nasMessageContainer}
	}

	return marshal(m)
}

func GetPduSessionEstablishmentRequest(pduSessionId uint8) []byte {
	m := &message.PDUSessEstReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		IntegrityProtectionMaxDataRate: &ie.IntegrityProtectionMaxDataRate{
			Uplink:   0xff,
			Downlink: 0xff,
		},
		PDUSessType: &ie.PDUSessType{Value: ie.PDUSessType_IPv4},
		SSCMode:     &ie.SSCMode{Mode: ie.SSCMODE1},
		// NOTE: the old packet also requested IP address allocation via NAS
		// signalling. The new ie.ExtCfgOptFromMs has no field for that
		// container and marshalFromMs never emits it, so it is dropped here.
		// free5gc's SMF only reads the DNS / P-CSCF / MTU requests, so the E2E
		// behaviour is unaffected; see the migration report for details.
		ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{
			FromMs: &ie.ExtCfgOptFromMs{
				DNSV4Req: true,
				DNSV6Req: true,
			},
		},
	}

	return marshal(m)
}

func GetUlNasTransport_PduSessionEstablishmentRequest(pduSessionId uint8, requestType uint8, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionEstablishmentRequest(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshal(m)
}

func GetUlNasTransport_PduSessionModificationRequest(pduSessionId uint8, requestType uint8, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionModificationRequest(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshal(m)
}

func GetPduSessionModificationRequest(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessModReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionModificationComplete(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessModComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionModificationCommandReject(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessModCmdRej{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		// Cause5GSM is a mandatory V field in this message.
		Cause5GSM: &ie.Cause5GSM{},
	})
}

func GetPduSessionReleaseRequest(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessRelReq{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionReleaseComplete(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessRelComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
	})
}

func GetPduSessionReleaseReject(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessRelRej{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		// Cause5GSM is a mandatory V field in this message.
		Cause5GSM: &ie.Cause5GSM{},
	})
}

func GetPduSessionAuthenticationComplete(pduSessionId uint8) []byte {
	return marshal(&message.PDUSessAuthComplete{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		EAPMsg:    &ie.EAPMsg{Eap: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
	})
}

func GetUlNasTransport_PduSessionCommonData(pduSessionId uint8, types string) []byte {
	var payload []byte
	switch types {
	case PDUSesModiReq:
		payload = GetPduSessionModificationRequest(pduSessionId)
	case PDUSesModiCmp:
		payload = GetPduSessionModificationComplete(pduSessionId)
	case PDUSesModiCmdRej:
		payload = GetPduSessionModificationCommandReject(pduSessionId)
	case PDUSesRelReq:
		payload = GetPduSessionReleaseRequest(pduSessionId)
	case PDUSesRelCmp:
		payload = GetPduSessionReleaseComplete(pduSessionId)
	case PDUSesRelRej:
		payload = GetPduSessionReleaseReject(pduSessionId)
	case PDUSesAuthCmp:
		payload = GetPduSessionAuthenticationComplete(pduSessionId)
	}

	return marshal(newULNASTransport(pduSessionId, payload))
}

func GetIdentityResponse(mobileIdentity *ie.MobileId5GS) []byte {
	return marshal(&message.IdRsp{MobileId: mobileIdentity})
}

func GetNotificationResponse(pDUSessionStatus []uint8) []byte {
	m := &message.NotifRsp{PDUSessStatus: &ie.PDUSessStatus{}}
	setPsiFromBuffer(&m.PDUSessStatus.Psi, pDUSessionStatus)
	return marshal(m)
}

// setPsiFromBuffer converts the raw PDU session status bitmap the old API
// exposed as a byte buffer into the new ie.Psi bool array. Bit i of octet n
// maps to PSI[n*8+i], matching TS 24.501 9.11.3.44.
func setPsiFromBuffer(psi *ie.Psi, buf []uint8) {
	for octet, b := range buf {
		for bit := 0; bit < 8; bit++ {
			idx := octet*8 + bit
			if idx >= len(psi.PSI) {
				return
			}
			psi.PSI[idx] = b&(1<<uint(bit)) != 0
		}
	}
}

func GetConfigurationUpdateComplete() []byte {
	return marshal(&message.CfgUpdateComplete{})
}

func GetServiceRequest(serviceType uint8) []byte {
	m := &message.SvcReq{
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxTypeNative,
			Ksi: 0x01,
		},
		SvcType: &ie.SvcType{Value: ie.ConstSvcType(serviceType)},
		TMSI5GS: &ie.MobileId5GS{
			TypeOfId: ie.IdType_5GS_TMSI,
			AMFSetID: uint16(0xFE) << 2,
			TMSI5G:   [4]byte{0, 0, 0, 1},
		},
	}

	switch ie.ConstSvcType(serviceType) {
	case ie.SvcType_MobileTermSvc:
		m.AllowedPDUSessStatus = &ie.AllowedPDUSessStatus{}
		setPsiFromBuffer(&m.AllowedPDUSessStatus.Psi, []uint8{0x00, 0x08})
	case ie.SvcType_Data:
		m.UplinkDataStatus = &ie.UplinkDataStatus{}
		setPsiFromBuffer(&m.UplinkDataStatus.Psi, []uint8{0x00, 0x04})
	case ie.SvcType_Signalling:
	}

	return marshal(m)
}

func GetAuthenticationResponse(authenticationResponseParam []uint8, eapMsg string) []byte {
	m := &message.AuthRsp{}

	if len(authenticationResponseParam) > 0 {
		m.AuthRspParam = &ie.AuthRspParam{Res: authenticationResponseParam[0:16]}
	} else if eapMsg != "" {
		rawEapMsg, err := base64.StdEncoding.DecodeString(eapMsg)
		if err != nil {
			fmt.Printf("EAP decode error: %+v\n", err)
		}
		m.EAPMsg = &ie.EAPMsg{Eap: rawEapMsg}
	}

	return marshal(m)
}

func GetAuthenticationFailure(cause5GMM uint8, authenticationFailureParam []uint8) []byte {
	m := &message.AuthFailure{
		Cause5GMM: &ie.Cause5GMM{Value: cause5GMM},
	}

	if cause5GMM == ie.Cause5GMM_SynchFailure {
		m.AuthFailureParam = &ie.AuthFailureParam{Value: authenticationFailureParam}
	}

	return marshal(m)
}

func GetRegistrationComplete(sorTransparentContainer []uint8) []byte {
	m := &message.RegComplete{}

	if sorTransparentContainer != nil {
		m.SORTransparentCntr = &ie.SORTransparentCntr{}
	}

	return marshal(m)
}

// TS 24.501 8.2.26.
func GetSecurityModeComplete(nasMessageContainer []uint8) []byte {
	m := &message.SecModeComplete{
		// Same three digits the old packet set (digit 1, P-1 and P); the rest
		// stay zero. The new library additionally pads the trailing unused BCD
		// nibble with 0xF as TS 23.003 requires, which the old one left at 0.
		IMEISV: &ie.MobileId5GS{
			TypeOfId:     ie.IdType_5GS_IMEISV,
			OddEvenIndic: 0,
			IMEISV:       [16]uint8{1, 1, 1},
		},
	}

	if nasMessageContainer != nil {
		m.NASMsgCntr = &ie.NASMsgCntr{Contents: nasMessageContainer}
	}

	return marshal(m)
}

func GetSecurityModeReject(cause5GMM uint8) []byte {
	return marshal(&message.SecModeRej{
		Cause5GMM: &ie.Cause5GMM{Value: cause5GMM},
	})
}

func GetDeregistrationRequest(accessType uint8, switchOff uint8, ngKsi uint8,
	mobileIdentity5GS *ie.MobileId5GS,
) []byte {
	return marshal(&message.DeregReqUEOrig{
		DeregType: &ie.DeregType{
			AccessType:    accessType,
			Switchoff:     switchOff != 0,
			ReregRequired: false,
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: ie.SecCtxType(ngKsi),
			Ksi: ngKsi,
		},
		MobileId5GS: mobileIdentity5GS,
	})
}

func GetDeregistrationAccept() []byte {
	return marshal(&message.DeregAcceptUETerm{})
}

func GetStatus5GMM(cause uint8) []byte {
	return marshal(&message.Status5GMM{
		Cause5GMM: &ie.Cause5GMM{Value: cause},
	})
}

func GetStatus5GSM(pduSessionId uint8, cause uint8) []byte {
	return marshal(&message.Status5GSM{
		PDUSessId: pduSessionId,
		PTI:       0x00,
		Cause5GSM: &ie.Cause5GSM{Value: cause},
	})
}

func GetUlNasTransport_Status5GSM(pduSessionId uint8, cause uint8) []byte {
	return marshal(newULNASTransport(pduSessionId, GetStatus5GSM(pduSessionId, cause)))
}

func GetUlNasTransport_PduSessionReleaseRequest(pduSessionId uint8) []byte {
	return marshal(newULNASTransport(pduSessionId, GetPduSessionReleaseRequest(pduSessionId)))
}

func GetUlNasTransport_PduSessionReleaseComplete(pduSessionId uint8, requestType uint8, dnnString string,
	sNssai *models.Snssai,
) []byte {
	m := newULNASTransport(pduSessionId, GetPduSessionReleaseComplete(pduSessionId))
	setULNASTransportRouting(m, requestType, dnnString, sNssai)
	return marshal(m)
}
