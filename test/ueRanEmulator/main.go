package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"test"
	"test/nasTestpacket"

	"github.com/calee0219/fatal"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

type n2Amf struct {
	Addr string `yaml:"addr,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type n2Ran struct {
	Addr string `yaml:"addr,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type n3Upf struct {
	Addr string `yaml:"addr,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type n3Ran struct {
	Addr string `yaml:"addr,omitempty"`
	Port uint16 `yaml:"port,omitempty"`
}

type rawUDP struct {
	SrcIP   string `yaml:"srcIP,omitempty"`
	SrcPort uint16 `yaml:"srcPort,omitempty"`
	DstIP   string `yaml:"dstIP,omitempty"`
	DstPort uint16 `yaml:"dstPort,omitempty"`
}

type snssai struct {
	Sst int32  `yaml:"sst,omitempty"`
	Sd  string `yaml:"sd,omitempty"`
}

type Configuration struct {
	N2Amf *n2Amf `yaml:"n2Amf,omitempty"`

	N2Ran *n2Ran `yaml:"n2Ran,omitempty"`

	N3Upf *n3Upf `yaml:"n3Upf,omitempty"`

	N3Ran *n3Ran `yaml:"n3Ran,omitempty"`

	RawUDP *rawUDP `yaml:"rawUDP,omitempty"`

	Supi string `yaml:"supi,omitempty"`

	Mcc string `yaml:"mcc,omitempty"`

	Mnc string `yaml:"mnc,omitempty"`

	K string `yaml:"k,omitempty"`

	Opc string `yaml:"opc,omitempty"`

	Op string `yaml:"op,omitempty"`

	NgapID int64 `yaml:"ngapID,omitempty"`

	TeID uint32 `yaml:"teID,omitempty"`

	Snssai *snssai `yaml:"snssai,omitempty"`
}

var uerancfg Configuration

func hexCharToByte(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}

	return 0
}

// encodeSuci builds the SUCI mobile identity. The new nas API models the SUCI
// as structured fields (PLMN, routing indicator, scheme, MSIN digits) and does
// the BCD packing itself, so the manual octet assembly the old version needed
// is gone.
func encodeSuci(imsi []byte, mncLen int) *ie.MobileId5GS {
	mcc := string(imsi[0:3])
	var mnc, msin string
	if mncLen > 2 {
		mnc, msin = string(imsi[3:6]), string(imsi[6:])
	} else {
		mnc, msin = string(imsi[3:5]), string(imsi[5:])
	}

	suci := &ie.MobileId5GS{
		TypeOfId:   ie.IdType_5GS_SUCI,
		SUPIFormat: 0, // IMSI
		PlmnId:     ie.PlmnId{MCC: mcc, MNC: mnc},
	}
	for i := 0; i < len(msin) && i < len(suci.MSINDigits); i++ {
		suci.MSINDigits[i] = hexCharToByte(msin[i])
	}
	suci.MSINLength = len(msin)

	return suci
}

func ueRanEmulator() error {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(
		uerancfg.N2Amf.Addr, uerancfg.N2Ran.Addr, int(uerancfg.N2Amf.Port), int(uerancfg.N2Ran.Port))
	if err != nil {
		err = fmt.Errorf("ConnectToAmf: %v", err)
		return err
	}
	defer func() {
		errConn := conn.Close()
		if errConn != nil {
			fatal.Fatalf("conn Close error in ueRanEmulator: %+v", errConn)
		}
	}()
	fmt.Printf("[UERANEM] Connect to AMF successfully\n")

	// RAN connect to UPF
	upfConn, err := test.ConnectToUpf(
		uerancfg.N3Ran.Addr, uerancfg.N3Upf.Addr, int(uerancfg.N3Ran.Port), int(uerancfg.N3Upf.Port))
	if err != nil {
		err = fmt.Errorf("ConnectToUpf: %v", err)
		return err
	}
	defer func() {
		errConn := upfConn.Close()
		if errConn != nil {
			fatal.Fatalf("upfConn Close error in ueRanEmulator: %+v", errConn)
		}
	}()
	fmt.Printf("[UERANEM] Connect to UPF successfully\n")

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc", "", "", "")
	if err != nil {
		err = fmt.Errorf("GetNGSetupRequest: %v", err)
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	if err != nil {
		return err
	}
	_, err = ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return err
	}
	fmt.Printf("[UERANEM] NGSetup successfully\n")

	// New UE
	// ue := test.NewRanUeContext("imsi-208930000007487", 1, message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2,
	//	models.AccessType_3_GPP_ACCESS)
	ue := test.NewRanUeContext(uerancfg.Supi, uerancfg.NgapID, message.AlgCiphering128NEA0, message.AlgIntegrity128NIA2,
		models.AccessType_3_GPP_ACCESS)
	ue.AmfUeNgapId = uerancfg.NgapID
	ue.AuthenticationSubs = test.GetAuthSubscription(uerancfg.K, uerancfg.Opc, uerancfg.Op)

	mobileIdentity5GS := encodeSuci([]byte(strings.TrimPrefix(uerancfg.Supi, "imsi-")), len(uerancfg.Mnc))

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(ie.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	if err != nil {
		return err
	}
	ngapMsg, err := ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return err
	}

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.(*ngapMessage.DownlinkNASTransport))
	if nasPdu == nil {
		err = fmt.Errorf("GetNasPdu failed")
		return err
	}
	rand := nasPdu.AuthenticationRequest.GetRANDValue()

	var mncPad string
	if len(uerancfg.Mnc) == 2 {
		mncPad = "0" + uerancfg.Mnc
	} else {
		mncPad = uerancfg.Mnc
	}
	snName := "5G:mnc" + mncPad + ".mcc" + uerancfg.Mcc + ".3gppnetwork.org"

	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], snName)

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	if err != nil {
		return err
	}
	_, err = ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return err
	}

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(ie.RegType_InitialReg,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(
		ue, pdu, message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx, true, true)
	if err != nil {
		return err
	}
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	if err != nil {
		return err
	}
	_, err = ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return err
	}

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return err
	}
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive UE Configuration Update Command Msg
	n, err = conn.Read(recvMsg)
	if err != nil {
		return nil
	}
	_, err = ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return nil
	}
	fmt.Printf("[UERANEM] Initial-Registration completed\n")

	time.Sleep(100 * time.Millisecond)
	// send GetPduSessionEstablishmentRequest Msg

	sNssai := models.Snssai{
		Sst: uerancfg.Snssai.Sst,
		Sd:  uerancfg.Snssai.Sd,
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(
		10, uint8(ie.ReqType_InitialReq), "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, message.SecHdrTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		return err
	}
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	if err != nil {
		return err
	}
	_, err = ngapMessage.Parse(recvMsg[:n])
	if err != nil {
		return err
	}

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, uerancfg.N3Ran.Addr)
	if err != nil {
		return err
	}
	_, err = conn.Write(sendMsg)
	if err != nil {
		return err
	}
	fmt.Printf("[UERANEM] PDU session establishment completed\n")

	// wait 1s
	time.Sleep(1 * time.Second)

	// infinite loop to send UDP with GTP
	for {
		fmt.Printf("[UERANEM] Send GTP packet to UPF\n")
		if err = sendGTP(upfConn, "helloworld"); err != nil {
			fmt.Printf("[UERANEM] Fail to send GTP packet!\n")
			break
		}
		time.Sleep(1 * time.Second)
	}

	return err
}

func sendGTP(conn *net.UDPConn, msg string) error {
	pkt, err := test.BuildRawUdpIp(
		uerancfg.RawUDP.SrcIP, uerancfg.RawUDP.DstIP, uerancfg.RawUDP.SrcPort, uerancfg.RawUDP.DstPort, []byte(msg))
	if err != nil {
		return err
	}

	// build GTPv1 header
	gtpHdr, err := test.BuildGTPv1Header(false, 0, false, 0, false, 0, uint16(len(pkt)), uerancfg.TeID)
	if err != nil {
		return err
	}

	tt := append(gtpHdr, pkt...)

	// send to socket
	_, err = conn.Write(tt)
	return err
}

func main() {
	app := cli.NewApp()
	app.Name = "UE RAN Emulator"
	app.Usage = "./ueranem"
	app.Action = action
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Value:   "./config/ueranem.yaml",
			Usage:   "Load configuration from `FILE`",
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func initConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		err = fmt.Errorf("ReadFile: %v", err)
		return err
	}

	uerancfg = Configuration{}

	if err = yaml.Unmarshal([]byte(content), &uerancfg); err != nil {
		err = fmt.Errorf("Unmarshal: %v", err)
		return err
	}

	fmt.Printf("Load configuration %s successfully\n", f)
	return nil
}

func action(c *cli.Context) error {
	if err := initConfigFactory(c.String("config")); err != nil {
		return err
	}
	err := ueRanEmulator()
	return err
}
