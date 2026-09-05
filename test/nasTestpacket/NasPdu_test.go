package nasTestpacket

import (
	"testing"

	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// The E2E suite has no golden baseline of its own, so this is the safety net
// for the builders in this package: every message must be non-empty and must
// parse back with the library's own decoder. That catches the failure mode a
// migration is most likely to introduce -- a message that still compiles but
// no longer produces a well-formed NAS PDU.

func testSnssai() *models.Snssai {
	return &models.Snssai{Sst: 1, Sd: "010203"}
}

func TestGSMBuildersParseBack(t *testing.T) {
	cases := map[string][]byte{
		"PduSessionEstablishmentRequest":   GetPduSessionEstablishmentRequest(10),
		"PduSessionModificationRequest":    GetPduSessionModificationRequest(10),
		"PduSessionModificationComplete":   GetPduSessionModificationComplete(10),
		"PduSessionModificationCmdReject":  GetPduSessionModificationCommandReject(10),
		"PduSessionReleaseRequest":         GetPduSessionReleaseRequest(10),
		"PduSessionReleaseComplete":        GetPduSessionReleaseComplete(10),
		"PduSessionReleaseReject":          GetPduSessionReleaseReject(10),
		"PduSessionAuthenticationComplete": GetPduSessionAuthenticationComplete(10),
		"Status5GSM":                       GetStatus5GSM(10, 0x2b),
	}

	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if len(b) == 0 {
				t.Fatal("produced empty bytes")
			}
			if _, err := message.ParseGSM(b); err != nil {
				t.Fatalf("ParseGSM failed: %v (bytes=%x)", err, b)
			}
		})
	}
}

func TestGMMBuildersParseBack(t *testing.T) {
	cases := map[string][]byte{
		"ServiceRequest_Signalling":   GetServiceRequest(0x00),
		"ServiceRequest_Data":         GetServiceRequest(0x01),
		"ServiceRequest_MT":           GetServiceRequest(0x02),
		"AuthenticationResponse":      GetAuthenticationResponse(make([]uint8, 16), ""),
		"AuthenticationFailure":       GetAuthenticationFailure(0x15, make([]uint8, 14)),
		"RegistrationComplete":        GetRegistrationComplete(nil),
		"SecurityModeComplete":        GetSecurityModeComplete(nil),
		"SecurityModeReject":          GetSecurityModeReject(0x18),
		"DeregistrationAccept":        GetDeregistrationAccept(),
		"Status5GMM":                  GetStatus5GMM(0x2b),
		"ConfigurationUpdateComplete": GetConfigurationUpdateComplete(),
		"NotificationResponse":        GetNotificationResponse([]uint8{0x00, 0x08}),
		"UlNasTransport_EstReq": GetUlNasTransport_PduSessionEstablishmentRequest(
			10, 1, "internet", testSnssai()),
		"UlNasTransport_ModReq": GetUlNasTransport_PduSessionModificationRequest(
			10, 1, "internet", testSnssai()),
		"UlNasTransport_RelReq": GetUlNasTransport_PduSessionReleaseRequest(10),
		"UlNasTransport_RelCmp": GetUlNasTransport_PduSessionReleaseComplete(
			10, 1, "internet", testSnssai()),
		"UlNasTransport_Status5GSM": GetUlNasTransport_Status5GSM(10, 0x2b),
		"UlNasTransport_CommonData": GetUlNasTransport_PduSessionCommonData(10, PDUSesRelReq),
	}

	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if len(b) == 0 {
				t.Fatal("produced empty bytes")
			}
			if _, err := message.ParseGMM(b); err != nil {
				t.Fatalf("ParseGMM failed: %v (bytes=%x)", err, b)
			}
		})
	}
}

// The ULNASTransport builders must carry the N1 SM payload through unchanged --
// that payload is what the AMF forwards to the SMF, so a truncated or reordered
// container would break session management without breaking the outer message.
func TestULNASTransportCarriesPayload(t *testing.T) {
	payload := GetPduSessionReleaseRequest(10)
	b := GetUlNasTransport_PduSessionReleaseRequest(10)

	m, err := message.ParseGMM(b)
	if err != nil {
		t.Fatalf("ParseGMM failed: %v", err)
	}
	ul, ok := m.(*message.ULNASTransport)
	if !ok {
		t.Fatalf("expected *message.ULNASTransport, got %T", m)
	}
	if ul.PayloadCntr == nil {
		t.Fatal("PayloadCntr is nil")
	}
	if got := ul.PayloadCntr.Contents; string(got) != string(payload) {
		t.Errorf("payload mismatch:\n got %x\nwant %x", got, payload)
	}
	if ul.PDUSessID == nil || ul.PDUSessID.Value != 10 {
		t.Errorf("PDUSessID = %+v, want 10", ul.PDUSessID)
	}
}
