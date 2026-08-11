package test_test

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"test"
	"test/consumerTestdata/UDM/TestGenAuthData"
	"test/nasTestpacket"
	"test/ngapTestpacket"
	"testing"
	"time"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/aper"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/sctp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	amfN2Addr  = "127.0.0.1"
	mranN2Addr = "127.0.0.1"
	sranN2Addr = "127.0.0.2"
	upfN3Addr  = "10.200.200.102"
	mranN3Addr = "10.200.200.1"
	sranN3Addr = "10.200.200.2"

	tMranN3Addr = sranN3Addr
	tSranN3Addr = mranN3Addr

	googleDNS    = "9.9.10.10"
	cloudFareDNS = "9.9.9.9"

	ueIp = "10.60.0.1"
	loIp = "10.60.0.101"

	amfPort    = 38412
	mranN2Port = 9487
	sranN2Port = 9488
	mupfN3Port = 2152
	supfN3Port = 2152
	mranN3Port = 2152
	sranN3Port = 2152

	servingPlmnId = "20893"

	mranULTeid = "00000002"
	sranULTeid = "00000003"
	mranDLTeid = "\x00\x00\x00\x01"
	sranDLTeid = "\x00\x00\x00\x02"

	tMranULTeid = "00000002"
	tSranULTeid = "00000003"
	tMranDLTeid = "\x00\x00\x00\x03"
	tSranDLTeid = "\x00\x00\x00\x04"

	ENABLE_DC_AT_PDU_SESSION_ESTABLISHMENT    = true
	UN_ENABLE_DC_AT_PDU_SESSION_ESTABLISHMENT = false

	ENABLE_DC_AT_PDU_SESSION_MODIFY_INDICATION  = true
	DISABLE_DC_AT_PDU_SESSION_MODIFY_INDICATION = false

	EXPECTED_ERROR    = true
	EXPECTED_NO_ERROR = false
)

func connectRANsToAMF(t *testing.T) (*sctp.SCTPConn, *sctp.SCTPConn) {
	// Master RAN connect to AMF
	MranConn, err := test.ConnectToAmf(amfN2Addr, mranN2Addr, amfPort, mranN2Port)
	if err != nil {
		t.Logf("Master RAN connect to AMF failed: %v", err)
		return nil, nil
	}
	assert.NotNil(t, MranConn)

	// Second RAN connect to AMF
	SranConn, err := test.ConnectToAmf(amfN2Addr, sranN2Addr, amfPort, sranN2Port)
	if err != nil {
		t.Logf("Secondary RAN connect to AMF failed: %v", err)
		if MranConn != nil {
			MranConn.Close()
		}
		return nil, nil
	}
	assert.NotNil(t, SranConn)

	return MranConn, SranConn
}

func connectRANsToUPF(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	// Master RAN connect to UPF
	MupfConn, err := test.ConnectToUpf(mranN3Addr, upfN3Addr, mupfN3Port, mranN3Port)
	if err != nil {
		t.Errorf("Master RAN connect to UPF failed: %v", err)
		return nil, nil
	}
	assert.NotNil(t, MupfConn)

	// Second RAN connect to UPF
	SupfConn, err := test.ConnectToUpf(sranN3Addr, upfN3Addr, supfN3Port, sranN3Port)
	if err != nil {
		t.Errorf("Secondary RAN connect to UPF failed: %v", err)
		if MupfConn != nil {
			MupfConn.Close()
		}
		return nil, nil
	}
	assert.NotNil(t, SupfConn)

	return MupfConn, SupfConn
}

func nGsSetup(t *testing.T, MranConn *sctp.SCTPConn, SranConn *sctp.SCTPConn) {
	var n int
	var recvMsg = make([]byte, 2048)

	// send Master RAN NGSetupRequest Msg
	sendMsg, err := test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "MasterRAN", "", "\x01", "\xfe\xdc\xba")
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive Master RAN NGSetupResponse Msg
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome && ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// send Second RAN NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x03\x04"), 24, "SecondRAN", "\x00\x00\x11", "\x01", "\xfe\xdc\xba")
	assert.Nil(t, err)
	_, err = SranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive Second RAN NGSetupResponse Msg
	n, err = SranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome && ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeNGSetup, "No NGSetupResponse received.")
}

func newUEAndInitialRegistration(t *testing.T, MranConn *sctp.SCTPConn) *test.RanUeContext {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)
	var err error

	// New UE
	ue := test.NewRanUeContext("imsi-208930000007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType_3_GPP_ACCESS)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)

	// insert UE data to MongoDB
	test.DelUeFromMongoDB(t, ue, servingPlmnId)
	test.InsertUeToMongoDB(t, ue, servingPlmnId)

	// send InitialUeMessage(Registration Request)(imsi-208930000007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    13, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage && ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeDownlinkNASTransport, "No NAS Authentication Request received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.(*ngapMessage.DownlinkNASTransport))
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive UE Configuration Update Command Msg
	recvUeConfigUpdateCmd(t, recvMsg, MranConn)

	time.Sleep(100 * time.Millisecond)

	return ue
}

func pduSessionEstablishment(t *testing.T, ue *test.RanUeContext, MranConn *sctp.SCTPConn, enableDC bool) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)
	var err error

	getPDUSessionResourceSetupResponseWithDC := func(pduSessionID, amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
		message := ngapTestpacket.BuildPDUSessionResourceSetupResponseWithDC(
			pduSessionID, amfUeNgapID, ranUeNgapID, mranN3Addr, mranDLTeid, "", "")
		if enableDC {
			message = ngapTestpacket.BuildPDUSessionResourceSetupResponseWithDC(
				pduSessionID, amfUeNgapID, ranUeNgapID, mranN3Addr, mranDLTeid, sranN3Addr, sranDLTeid)
		}
		return message.MarshalBinary()
	}

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "fedcba",
	}
	pdu := nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap PDU Session Resource Setup Request Msg
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeInitiatingMessage &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodePDUSessionResourceSetup,
		"No PDU Session Resource Setup Request received.")

	// send ngap PDU Session Resource Setup Response Msg
	sendMsg, err = getPDUSessionResourceSetupResponseWithDC(10, ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)
}

func icmpTest(t *testing.T, upfConn *net.UDPConn, ulTeid, destIp string, expectedError bool) {
	gtpHdr, err := hex.DecodeString(fmt.Sprintf("32ff0034%s00000000", ulTeid))
	assert.Nil(t, err)
	icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	assert.Nil(t, err)

	ipv4hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		Protocol: 1,
		Flags:    0,
		TotalLen: 48,
		TTL:      64,
		Src:      net.ParseIP(ueIp).To4(),
		Dst:      net.ParseIP(destIp).To4(),
		ID:       1,
	}
	checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	ipv4hdr.Checksum = int(checksum)

	v4HdrBuf, err := ipv4hdr.Marshal()
	assert.Nil(t, err)
	tt := append(gtpHdr, v4HdrBuf...)

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: 12394, Seq: 1,
			Data: icmpData,
		},
	}
	b, err := m.Marshal(nil)
	assert.Nil(t, err)
	b[2] = 0xaf
	b[3] = 0x88
	_, err = upfConn.Write(append(tt, b...))
	assert.Nil(t, err)

	recvMsg := make([]byte, 2048)
	err = upfConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	assert.Nil(t, err)
	n, err := upfConn.Read(recvMsg)
	if expectedError {
		assert.NotNil(t, err)
	} else {
		assert.Nil(t, err)
		assert.Equal(t, 64, n)
	}
	err = upfConn.SetReadDeadline(time.Time{})
	assert.Nil(t, err)
}

func pduSessionModifyIndication(t *testing.T, ue *test.RanUeContext, MranConn *sctp.SCTPConn, enableDC bool) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)
	var err error

	getPDUSessionResourceModifyIndication := func(pduSessionID, amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
		secondaryIP, secondaryTEID := "", ""
		if enableDC {
			secondaryIP, secondaryTEID = sranN3Addr, sranDLTeid
		}
		message := ngapTestpacket.BuildPDUSessionResourceModifyIndicationWithDC(
			pduSessionID, amfUeNgapID, ranUeNgapID, mranN3Addr, mranDLTeid, secondaryIP, secondaryTEID)
		return message.MarshalBinary()
	}

	// send pdu session resource modify indication
	sendMsg, err = getPDUSessionResourceModifyIndication(10, ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = MranConn.Write(sendMsg)
	assert.Nil(t, err)

	// receive pdu session resource modify confirm
	n, err = MranConn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.MessageType() == ngapMessage.MessageTypeSuccessfulOutcome &&
		ngapPdu.ProcedureCode() == ngapMessage.ProcedureCodePDUSessionResourceModifyIndication,
		"No PDU Session Resource Modify Confirm received.")

	confirm, ok := ngapPdu.(*ngapMessage.PDUSessionResourceModifyConfirm)
	require.True(t, ok)
	if confirm.PDUSessionResourceFailedToModifyListModCfm != nil {
		t.Fatalf("PDU session modify indication request failed")
	}
	if confirm.PDUSessionResourceModifyListModCfm != nil {
		t.Log("PDU session modify indication request successful")
	}

	time.Sleep(1 * time.Second)
}

func pathSwitchWithDC(t *testing.T, ue *test.RanUeContext, MranConn *sctp.SCTPConn, SranConn *sctp.SCTPConn) {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)
	var err error

	getPathSwitchRequestWithDC := func(pduSessionID, amfUeNgapID, ranUeNgapID int64) ([]byte, error) {
		message := ngapTestpacket.BuildPathSwitchRequestWithDC(
			pduSessionID, amfUeNgapID, ranUeNgapID, tMranN3Addr, tMranDLTeid, tSranN3Addr, tSranDLTeid)
		return message.MarshalBinary()
	}

	// send path switch request
	sendMsg, err = getPathSwitchRequestWithDC(10, ue.AmfUeNgapId, ue.RanUeNgapId)
	if err != nil {
		t.Fatalf("Failed to get path switch request with DC: %+v", err)
	}
	_, err = SranConn.Write(sendMsg) // send from secondary RAN since it is the new master RAN
	if err != nil {
		t.Fatalf("Failed to send path switch request to Master RAN: %+v", err)
	}

	// receive path switch request acknowledge
	n, err = SranConn.Read(recvMsg)
	if err != nil {
		t.Fatalf("Failed to receive path switch request acknowledge from Master RAN: %+v", err)
	}

	ngapPdu, err := ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		t.Fatalf("Failed to decode path switch request acknowledge from Master RAN: %+v", err)
	}

	ack, ok := ngapPdu.(*ngapMessage.PathSwitchRequestAcknowledge)
	require.True(t, ok)
	for _, item := range ack.PDUSessionResourceSwitchedList.List {
		var data ngapIE.PathSwitchRequestAcknowledgeTransfer
		err = ngapIE.UnmarshalBinary([]byte(*item.PathSwitchRequestAcknowledgeTransfer), &data)
		if err != nil {
			t.Fatalf("Failed to unmarshal path switch request acknowledge transfer: %+v", err)
		}

		ulTunnel := data.ULNGUUPTNLInformation.Choice.(*ngapIE.GTPTunnel)
		assert.Equal(t, aper.OctetString("\x00\x00\x00\x02"), ulTunnel.GTPTEID.Value)
		if data.IEExtensions != nil {
			for _, extension := range data.IEExtensions.List {
				if extension.Id.Value == ngapIE.ProtocolIEIDAdditionalNGUUPTNLInformation {
					additional := extension.AdditionalNGUUPTNLInformation.List[0].ULNGUUPTNLInformation
					additionalTunnel := additional.Choice.(*ngapIE.GTPTunnel)
					assert.Equal(t, aper.OctetString("\x00\x00\x00\x03"), additionalTunnel.GTPTEID.Value)
				}
			}
		}
	}
}

func waitForGTPEndMarker(t *testing.T, MupfConn *net.UDPConn, SupfConn *net.UDPConn) {
	/*
		After successfully path switch, wait for GTP end marker to be sent by UPF
		Packet format will be (totally 8 bytes):
			- \x30 : GTP-U version 1
			- \xfe : Message Type 254 (End Marker)
			- \x00\x00 : Length 0 (no payload)
			- \x00\x00\x00\x00 : TEID

		Recv from MupfConn: "\x30\xfe\x00\x00\x00\x00\x00\x01"
		Recv from SupfConn: "\x30\xfe\x00\x00\x00\x00\x00\x02"
	*/

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		recvMsg := make([]byte, 2048)
		n, err := MupfConn.Read(recvMsg)
		if err != nil {
			t.Fatalf("Failed to read from MupfConn: %+v", err)
		}
		assert.Equal(t, []byte{0x30, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, recvMsg[:n])
	}()

	go func() {
		defer wg.Done()

		recvMsg := make([]byte, 2048)
		n, err := SupfConn.Read(recvMsg)
		if err != nil {
			t.Fatalf("Failed to read from SupfConn: %+v", err)
		}
		assert.Equal(t, []byte{0x30, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, recvMsg[:n])
	}()
	wg.Wait()
}

func TestDC(t *testing.T) {
	// RANs connect to AMF
	MranConn, SranConn := connectRANsToAMF(t)
	if MranConn == nil || SranConn == nil {
		t.Fatal("Failed to connect to AMF")
		return
	}
	defer MranConn.Close()
	defer SranConn.Close()
	t.Log("Master RAN and Secondary RAN connect to AMF successfully")

	// RANs connect to UPF
	MupfConn, SupfConn := connectRANsToUPF(t)
	if MupfConn == nil || SupfConn == nil {
		t.Fatal("Failed to connect to UPF")
		return
	}
	defer MupfConn.Close()
	defer SupfConn.Close()
	t.Log("Master RAN and Secondary RAN connect to UPF successfully")

	// NGSetup
	nGsSetup(t, MranConn, SranConn)
	t.Log("Master RAN and Secondary RAN NGSetup successfully")

	// New UE and initial registration(NAS/NGAP)
	ue := newUEAndInitialRegistration(t, MranConn)
	defer test.DelUeFromMongoDB(t, ue, servingPlmnId)
	t.Log("New UE and initial registration(NAS/NGAP) successfully")

	// PDU Session Establishment
	pduSessionEstablishment(t, ue, MranConn, ENABLE_DC_AT_PDU_SESSION_ESTABLISHMENT)
	t.Log("PDU Session Establishment successfully")

	// ping test via master RAN
	t.Run("ping test via master RAN", func(t *testing.T) {
		icmpTest(t, MupfConn, mranULTeid, googleDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via master RAN successfully")
	})

	// ping test via Secondary RAN
	t.Run("ping test via Secondary RAN", func(t *testing.T) {
		icmpTest(t, SupfConn, sranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via Secondary RAN successfully")
	})

	NfTerminate()
}

func TestDynamicDC(t *testing.T) {
	// RANs connect to AMF
	MranConn, SranConn := connectRANsToAMF(t)
	if MranConn == nil || SranConn == nil {
		t.Fatal("Failed to connect to AMF")
		return
	}
	defer MranConn.Close()
	defer SranConn.Close()
	t.Log("Master RAN and Secondary RAN connect to AMF successfully")

	// RANs connect to UPF
	MupfConn, SupfConn := connectRANsToUPF(t)
	if MupfConn == nil || SupfConn == nil {
		t.Fatal("Failed to connect to UPF")
		return
	}
	defer MupfConn.Close()
	defer SupfConn.Close()
	t.Log("Master RAN and Secondary RAN connect to UPF successfully")

	// NGSetup
	nGsSetup(t, MranConn, SranConn)
	t.Log("Master RAN and Secondary RAN NGSetup successfully")

	// New UE and initial registration(NAS/NGAP)
	ue := newUEAndInitialRegistration(t, MranConn)
	defer test.DelUeFromMongoDB(t, ue, servingPlmnId)
	t.Log("New UE and initial registration(NAS/NGAP) successfully")

	// PDU Session Establishment
	pduSessionEstablishment(t, ue, MranConn, UN_ENABLE_DC_AT_PDU_SESSION_ESTABLISHMENT)
	t.Log("PDU Session Establishment successfully")

	// ICMP test before DC is enabled
	t.Run("ping test before DC is enabled", func(t *testing.T) {
		t.Run("ping test via master RAN", func(t *testing.T) {
			icmpTest(t, MupfConn, mranULTeid, googleDNS, EXPECTED_NO_ERROR)
			icmpTest(t, MupfConn, mranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		})

		t.Run("ping test via secondary RAN", func(t *testing.T) {
			icmpTest(t, SupfConn, sranULTeid, cloudFareDNS, EXPECTED_ERROR)
		})
	})

	// PDU Session Modify Indication Enable DC
	pduSessionModifyIndication(t, ue, MranConn, ENABLE_DC_AT_PDU_SESSION_MODIFY_INDICATION)
	t.Log("PDU Session Modify Indication successfully")

	// ICMP test after DC is enabled
	t.Run("ping test after DC is enabled", func(t *testing.T) {
		t.Run("ping test via master RAN", func(t *testing.T) {
			icmpTest(t, MupfConn, mranULTeid, googleDNS, EXPECTED_NO_ERROR)
		})

		t.Run("ping test via secondary RAN", func(t *testing.T) {
			icmpTest(t, SupfConn, sranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		})
	})

	// PDU Session Modify Indication Disable DC
	pduSessionModifyIndication(t, ue, MranConn, DISABLE_DC_AT_PDU_SESSION_MODIFY_INDICATION)
	t.Log("PDU Session Modify Indication successfully")

	// ICMP test after DC is disabled
	t.Run("ping test after DC is disabled", func(t *testing.T) {
		t.Run("ping test via master RAN", func(t *testing.T) {
			icmpTest(t, MupfConn, mranULTeid, googleDNS, EXPECTED_NO_ERROR)
			icmpTest(t, MupfConn, mranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		})

		t.Run("ping test via secondary RAN", func(t *testing.T) {
			icmpTest(t, SupfConn, sranULTeid, cloudFareDNS, EXPECTED_ERROR)
		})
	})
}

func TestXnDCHandover(t *testing.T) {
	// RANs connect to AMF
	MranConn, SranConn := connectRANsToAMF(t)
	if MranConn == nil || SranConn == nil {
		t.Fatal("Failed to connect to AMF")
		return
	}
	defer MranConn.Close()
	defer SranConn.Close()
	t.Log("Master RAN and Secondary RAN connect to AMF successfully")

	// RANs connect to UPF
	MupfConn, SupfConn := connectRANsToUPF(t)
	if MupfConn == nil || SupfConn == nil {
		t.Fatal("Failed to connect to UPF")
		return
	}
	defer MupfConn.Close()
	defer SupfConn.Close()
	t.Log("Master RAN and Secondary RAN connect to UPF successfully")

	// NGSetup
	nGsSetup(t, MranConn, SranConn)
	t.Log("Master RAN and Secondary RAN NGSetup successfully")

	// New UE and initial registration(NAS/NGAP)
	ue := newUEAndInitialRegistration(t, MranConn)
	defer test.DelUeFromMongoDB(t, ue, servingPlmnId)
	t.Log("New UE and initial registration(NAS/NGAP) successfully")

	// PDU Session Establishment
	pduSessionEstablishment(t, ue, MranConn, ENABLE_DC_AT_PDU_SESSION_ESTABLISHMENT)
	t.Log("PDU Session Establishment successfully")

	// ping test via master RAN
	t.Run("ping test via master RAN", func(t *testing.T) {
		icmpTest(t, MupfConn, mranULTeid, googleDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via master RAN successfully")
	})

	// ping test via secondary RAN
	t.Run("ping test via secondary RAN", func(t *testing.T) {
		icmpTest(t, SupfConn, sranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via secondary RAN successfully")
	})

	/*
		Start handover:
			- Master RAN will handover to secondary RAN
			- Means that secondary RAN will be the new master RAN, and master RAN will be the new secondary RAN
	*/
	pathSwitchWithDC(t, ue, MranConn, SranConn)
	t.Log("Path Switch with DC successfully")

	// After successfully path switch, wait for GTP end marker to be sent by UPF
	waitForGTPEndMarker(t, MupfConn, SupfConn)
	t.Log("Wait for GTP end marker successfully")

	// ping test via new master RAN (original secondary RAN)
	t.Run("ping test via new master RAN (original secondary RAN)", func(t *testing.T) {
		icmpTest(t, SupfConn, tMranULTeid, googleDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via new master RAN successfully")
	})

	// ping test via new secondary RAN (original master RAN)
	t.Run("ping test via new secondary RAN (original master RAN)", func(t *testing.T) {
		icmpTest(t, MupfConn, tSranULTeid, cloudFareDNS, EXPECTED_NO_ERROR)
		t.Log("ICMP test via new secondary RAN successfully")
	})
}
