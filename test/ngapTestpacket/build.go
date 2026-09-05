// Package ngapTestpacket builds concrete NGAP messages for integration tests.
package ngapTestpacket

import (
	"encoding/hex"
	"net"

	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

func ids(amfUeNgapID, ranUeNgapID int64) (*ie.AMFUENGAPID, *ie.RANUENGAPID) {
	return &ie.AMFUENGAPID{Value: amfUeNgapID}, &ie.RANUENGAPID{Value: ranUeNgapID}
}

func normalReleaseCause() *ie.Cause {
	return &ie.Cause{Choice: &ie.CauseNas{Value: ie.CauseNasPresentNormalRelease}}
}

func testUserLocation() *ie.UserLocationInformation {
	return &ie.UserLocationInformation{Choice: &ie.UserLocationInformationNR{
		NRCGI: &ie.NRCGI{
			PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0x00, 0x01, 0x02, 0x00, 0x10}, BitLength: 36}},
		},
		TAI: &ie.TAI{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			TAC:          &ie.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
		},
	}}
}

func BuildNGSetupRequest() ngapMessage.Message {
	return &ngapMessage.NGSetupRequest{
		GlobalRANNodeID: &ie.GlobalRANNodeID{Choice: &ie.GlobalGNBID{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			GNBID: &ie.GNBID{Choice: &ie.GNBIDForGNBID{Value: aper.BitString{
				Bytes: []byte{0x45, 0x46, 0x47}, BitLength: 24,
			}}},
		}},
		RANNodeName: &ie.RANNodeName{Value: aper.PrintableString("free5GC")},
		SupportedTAList: &ie.SupportedTAList{List: []ie.SupportedTAItem{{
			TAC: &ie.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
			BroadcastPLMNList: &ie.BroadcastPLMNList{List: []ie.BroadcastPLMNItem{{
				PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
				TAISliceSupportList: &ie.SliceSupportList{List: []ie.SliceSupportItem{{
					SNSSAI: &ie.SNSSAI{SST: &ie.SST{Value: aper.OctetString{0x01}}, SD: &ie.SD{Value: aper.OctetString{0x11, 0x22, 0x33}}},
				}}},
			}}},
		}}},
		DefaultPagingDRX: &ie.PagingDRX{Value: ie.PagingDRXPresentV128},
	}
}

func BuildNGReset(partOfNGInterface *ie.UEAssociatedLogicalNGConnectionList) ngapMessage.Message {
	m := sampleNGReset().(*ngapMessage.NGReset)
	m.Cause = normalReleaseCause()
	if partOfNGInterface == nil {
		m.ResetType = &ie.ResetType{Choice: &ie.ResetAll{Value: ie.ResetAllPresentResetAll}}
	} else {
		m.ResetType = &ie.ResetType{Choice: partOfNGInterface}
	}
	return m
}

func BuildNGResetAcknowledge() ngapMessage.Message { return sampleNGResetAcknowledge() }
func BuildErrorIndication() ngapMessage.Message    { return sampleErrorIndication() }

func BuildInitialUEMessage(ranUeNgapID int64, nasPdu []byte, fiveGSTmsi string) ngapMessage.Message {
	m := sampleInitialUEMessage().(*ngapMessage.InitialUEMessage)
	m.RANUENGAPID.Value = ranUeNgapID
	m.NASPDU.Value = append(aper.OctetString(nil), nasPdu...)
	if fiveGSTmsi != "" {
		value, err := hex.DecodeString(fiveGSTmsi)
		if err == nil && len(value) >= 6 {
			m.FiveGSTMSI = &ie.FiveGSTMSI{
				AMFSetID:   &ie.AMFSetID{Value: aper.BitString{Bytes: value[:2], BitLength: 10}},
				AMFPointer: &ie.AMFPointer{Value: aper.BitString{Bytes: value[1:2], BitLength: 6}},
				FiveGTMSI:  &ie.FiveGTMSI{Value: aper.OctetString(value[len(value)-4:])},
			}
		}
	}
	return m
}

func BuildUplinkNasTransport(amfUeNgapID, ranUeNgapID int64, nasPdu []byte) ngapMessage.Message {
	m := sampleUplinkNASTransport().(*ngapMessage.UplinkNASTransport)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	m.NASPDU.Value = append(aper.OctetString(nil), nasPdu...)
	return m
}

func BuildUEContextReleaseRequest(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ngapMessage.Message {
	m := sampleUEContextReleaseRequest().(*ngapMessage.UEContextReleaseRequest)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	if len(pduSessionIDList) == 0 {
		m.PDUSessionResourceListCxtRelReq = nil
	} else {
		m.PDUSessionResourceListCxtRelReq = &ie.PDUSessionResourceListCxtRelReq{}
		for _, id := range pduSessionIDList {
			m.PDUSessionResourceListCxtRelReq.List = append(m.PDUSessionResourceListCxtRelReq.List,
				ie.PDUSessionResourceItemCxtRelReq{PDUSessionID: &ie.PDUSessionID{Value: id}})
		}
	}
	return m
}

func BuildUEContextReleaseComplete(amfUeNgapID, ranUeNgapID int64, pduSessionIDList []int64) ngapMessage.Message {
	m := sampleUEContextReleaseComplete().(*ngapMessage.UEContextReleaseComplete)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	if len(pduSessionIDList) == 0 {
		m.PDUSessionResourceListCxtRelCpl = nil
	} else {
		m.PDUSessionResourceListCxtRelCpl = &ie.PDUSessionResourceListCxtRelCpl{}
		for _, id := range pduSessionIDList {
			m.PDUSessionResourceListCxtRelCpl.List = append(m.PDUSessionResourceListCxtRelCpl.List,
				ie.PDUSessionResourceItemCxtRelCpl{PDUSessionID: &ie.PDUSessionID{Value: id}})
		}
	}
	return m
}

func BuildUEContextModificationResponse(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.UEContextModificationResponse{AMFUENGAPID: amfID, RANUENGAPID: ranID}
}

func BuildInitialContextSetupResponse(amfUeNgapID, ranUeNgapID int64, ipv4 string,
	pduSessionFailedList *ie.PDUSessionResourceFailedToSetupListCxtRes,
) ngapMessage.Message {
	m := sampleInitialContextSetupResponse().(*ngapMessage.InitialContextSetupResponse)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	if m.PDUSessionResourceSetupListCxtRes != nil && len(m.PDUSessionResourceSetupListCxtRes.List) != 0 {
		transfer := aper.OctetString(buildPDUSessionResourceSetupResponseTransfer(ipv4))
		m.PDUSessionResourceSetupListCxtRes.List[0].PDUSessionResourceSetupResponseTransfer = &transfer
	}
	m.PDUSessionResourceFailedToSetupListCxtRes = pduSessionFailedList
	return m
}

func BuildInitialContextSetupFailure(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := sampleInitialContextSetupFailure().(*ngapMessage.InitialContextSetupFailure)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildPathSwitchRequest(sourceAmfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := samplePathSwitchRequest().(*ngapMessage.PathSwitchRequest)
	m.SourceAMFUENGAPID, m.RANUENGAPID = ids(sourceAmfUeNgapID, ranUeNgapID)
	return m
}

func BuildHandoverRequestAcknowledge(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := sampleHandoverRequestAcknowledge().(*ngapMessage.HandoverRequestAcknowledge)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildHandoverFailure(amfUeNgapID int64) ngapMessage.Message {
	m := sampleHandoverFailure().(*ngapMessage.HandoverFailure)
	m.AMFUENGAPID.Value = amfUeNgapID
	return m
}

func BuildHandoverCancel() ngapMessage.Message { return sampleHandoverCancel() }

func BuildHandoverNotify(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := sampleHandoverNotify().(*ngapMessage.HandoverNotify)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildHandoverRequired(amfUeNgapID, ranUeNgapID int64, targetGNBID, targetCellID []byte) ngapMessage.Message {
	m := sampleHandoverRequired().(*ngapMessage.HandoverRequired)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	m.TargetID = targetRANNodeID(targetGNBID)
	m.SourceToTargetTransparentContainer.Value = GetSourceToTargetTransparentTransfer(targetGNBID, targetCellID)
	return m
}

func BuildPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID int64, ipv4 string) ngapMessage.Message {
	m := samplePDUSessionResourceSetupResponse().(*ngapMessage.PDUSessionResourceSetupResponse)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	if m.PDUSessionResourceSetupListSURes != nil && len(m.PDUSessionResourceSetupListSURes.List) != 0 {
		transfer := aper.OctetString(buildPDUSessionResourceSetupResponseTransfer(ipv4))
		m.PDUSessionResourceSetupListSURes.List[0].PDUSessionResourceSetupResponseTransfer = &transfer
	}
	return m
}

func BuildPDUSessionResourceSetupResponseForPaging(amfUeNgapID, ranUeNgapID int64, ipv4 string) ngapMessage.Message {
	return BuildPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID, ipv4)
}

func BuildPDUSessionResourceModifyResponse(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := samplePDUSessionResourceModifyResponse().(*ngapMessage.PDUSessionResourceModifyResponse)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildPDUSessionResourceReleaseResponse() ngapMessage.Message {
	return samplePDUSessionResourceReleaseResponse()
}

func BuildInitialContextSetupResponseForRegistraionTest(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	return BuildInitialContextSetupResponse(amfUeNgapID, ranUeNgapID, "", nil)
}

func BuildPDUSessionResourceSetupResponseForRegistrationTest(pduSessionID, amfUeNgapID, ranUeNgapID int64, ipv4 string) ngapMessage.Message {
	m := BuildPDUSessionResourceSetupResponse(amfUeNgapID, ranUeNgapID, ipv4).(*ngapMessage.PDUSessionResourceSetupResponse)
	if m.PDUSessionResourceSetupListSURes != nil && len(m.PDUSessionResourceSetupListSURes.List) != 0 {
		m.PDUSessionResourceSetupListSURes.List[0].PDUSessionID.Value = pduSessionID
	}
	return m
}

func BuildPDUSessionResourceReleaseResponseForReleaseTest(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := samplePDUSessionResourceReleaseResponse().(*ngapMessage.PDUSessionResourceReleaseResponse)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildAMFConfigurationUpdateFailure() ngapMessage.Message {
	return &ngapMessage.AMFConfigurationUpdateFailure{Cause: normalReleaseCause()}
}

func BuildUERadioCapabilityCheckResponse() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.UERadioCapabilityCheckResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		IMSVoiceSupportIndicator: &ie.IMSVoiceSupportIndicator{Value: ie.IMSVoiceSupportIndicatorPresentSupported},
	}
}

func BuildLocationReportingFailureIndication() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.LocationReportingFailureIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID, Cause: normalReleaseCause(),
	}
}

func BuildPDUSessionResourceNotify() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.PDUSessionResourceNotify{AMFUENGAPID: amfID, RANUENGAPID: ranID}
}

func BuildPDUSessionResourceModifyIndication(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	transfer := aper.OctetString{0x00}
	return &ngapMessage.PDUSessionResourceModifyIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceModifyListModInd: &ie.PDUSessionResourceModifyListModInd{List: []ie.PDUSessionResourceModifyItemModInd{{
			PDUSessionID: &ie.PDUSessionID{Value: 1},
			PDUSessionResourceModifyIndicationTransfer: &transfer,
		}}},
	}
}

func BuildUEContextModificationFailure(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.UEContextModificationFailure{
		AMFUENGAPID: amfID, RANUENGAPID: ranID, Cause: normalReleaseCause(),
	}
}

func BuildRRCInactiveTransitionReport() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.RRCInactiveTransitionReport{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		RRCState:                &ie.RRCState{Value: ie.RRCStatePresentInactive},
		UserLocationInformation: testUserLocation(),
	}
}

func BuildUplinkRanStatusTransfer(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	m := sampleUplinkRANStatusTransfer().(*ngapMessage.UplinkRANStatusTransfer)
	m.AMFUENGAPID, m.RANUENGAPID = ids(amfUeNgapID, ranUeNgapID)
	return m
}

func BuildNasNonDeliveryIndication(amfUeNgapID, ranUeNgapID int64, nasPdu aper.OctetString) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.NASNonDeliveryIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		NASPDU: &ie.NASPDU{Value: nasPdu}, Cause: normalReleaseCause(),
	}
}

func BuildRanConfigurationUpdate() ngapMessage.Message { return sampleRANConfigurationUpdate() }
func BuildAMFStatusIndication() ngapMessage.Message    { return sampleAMFStatusIndication() }

func BuildUplinkRanConfigurationTransfer() ngapMessage.Message {
	return &ngapMessage.UplinkRANConfigurationTransfer{}
}

func BuildUplinkUEAssociatedNRPPATransport() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.UplinkUEAssociatedNRPPaTransport{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		RoutingID: &ie.RoutingID{Value: aper.OctetString{0x01}},
		NRPPaPDU:  &ie.NRPPaPDU{Value: aper.OctetString{0x01, 0x02}},
	}
}

func BuildUplinkNonUEAssociatedNRPPATransport() ngapMessage.Message {
	return &ngapMessage.UplinkNonUEAssociatedNRPPaTransport{
		RoutingID: &ie.RoutingID{Value: aper.OctetString{0x01}},
		NRPPaPDU:  &ie.NRPPaPDU{Value: aper.OctetString{0x01, 0x02}},
	}
}

func BuildLocationReport() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.LocationReport{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		UserLocationInformation: testUserLocation(),
		LocationReportingRequestType: &ie.LocationReportingRequestType{
			EventType:  &ie.EventType{Value: ie.EventTypePresentDirect},
			ReportArea: &ie.ReportArea{Value: ie.ReportAreaPresentCell},
		},
	}
}

func BuildUERadioCapabilityInfoIndication() ngapMessage.Message {
	return sampleUERadioCapabilityInfoIndication()
}

func BuildAMFConfigurationUpdateAcknowledge() ngapMessage.Message {
	return &ngapMessage.AMFConfigurationUpdateAcknowledge{}
}

func BuildCellTrafficTrace(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	location := testUserLocation().Choice.(*ie.UserLocationInformationNR)
	return &ngapMessage.CellTrafficTrace{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		NGRANTraceID: &ie.NGRANTraceID{Value: aper.OctetString{0x02, 0xf8, 0x39, 0x01, 0x02, 0x03, 0x04, 0x05}},
		NGRANCGI:     &ie.NGRANCGI{Choice: location.NRCGI},
		TraceCollectionEntityIPAddress: &ie.TransportLayerAddress{Value: aper.BitString{
			Bytes: []byte{127, 0, 0, 1}, BitLength: 32,
		}},
	}
}

func BuildUERadioCapabilityCheckRequest(amfUeNgapID, ranUeNgapID int64) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.UERadioCapabilityCheckRequest{AMFUENGAPID: amfID, RANUENGAPID: ranID}
}

func BuildUETNLABindingReleaseRequest() ngapMessage.Message {
	amfID, ranID := ids(1, 2)
	return &ngapMessage.UETNLABindingReleaseRequest{AMFUENGAPID: amfID, RANUENGAPID: ranID}
}

func BuildRanConfigurationUpdateAck(diagnostics *ie.CriticalityDiagnostics) ngapMessage.Message {
	return &ngapMessage.RANConfigurationUpdateAcknowledge{CriticalityDiagnostics: diagnostics}
}

func BuildRanConfigurationUpdateFailure(timeToWait *ie.TimeToWait, diagnostics *ie.CriticalityDiagnostics) ngapMessage.Message {
	return &ngapMessage.RANConfigurationUpdateFailure{
		Cause: normalReleaseCause(), TimeToWait: timeToWait, CriticalityDiagnostics: diagnostics,
	}
}

func BuildAMFConfigurationUpdate(amfName string, guamiList []ie.ServedGUAMIItem,
	plmnList []ie.PLMNSupportItem, amfRelativeCapacity int64,
	addList *ie.AMFTNLAssociationToAddList, removeList *ie.AMFTNLAssociationToRemoveList,
	updateList *ie.AMFTNLAssociationToUpdateList,
) ngapMessage.Message {
	return &ngapMessage.AMFConfigurationUpdate{
		AMFName:                    &ie.AMFName{Value: aper.PrintableString(amfName)},
		ServedGUAMIList:            &ie.ServedGUAMIList{List: guamiList},
		RelativeAMFCapacity:        &ie.RelativeAMFCapacity{Value: amfRelativeCapacity},
		PLMNSupportList:            &ie.PLMNSupportList{List: plmnList},
		AMFTNLAssociationToAddList: addList, AMFTNLAssociationToRemoveList: removeList,
		AMFTNLAssociationToUpdateList: updateList,
	}
}

func BuildNGSetupResponse(amfName string, guamiList []ie.ServedGUAMIItem,
	plmnList []ie.PLMNSupportItem, amfRelativeCapacity int64,
) ngapMessage.Message {
	return &ngapMessage.NGSetupResponse{
		AMFName:             &ie.AMFName{Value: aper.PrintableString(amfName)},
		ServedGUAMIList:     &ie.ServedGUAMIList{List: guamiList},
		RelativeAMFCapacity: &ie.RelativeAMFCapacity{Value: amfRelativeCapacity},
		PLMNSupportList:     &ie.PLMNSupportList{List: plmnList},
	}
}

func BuildPDUSessionResourceModifyConfirm(amfUeNgapID, ranUeNgapID int64,
	modifyList ie.PDUSessionResourceModifyListModCfm,
	failedList ie.PDUSessionResourceFailedToModifyListModCfm,
	diagnostics *ie.CriticalityDiagnostics,
) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.PDUSessionResourceModifyConfirm{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceModifyListModCfm:         &modifyList,
		PDUSessionResourceFailedToModifyListModCfm: &failedList,
		CriticalityDiagnostics:                     diagnostics,
	}
}

func BuildPDUSessionResourceReleaseCommand(amfUeNgapID, ranUeNgapID int64,
	pagingPriority *ie.RANPagingPriority, nasPdu []byte,
	releaseList ie.PDUSessionResourceToReleaseListRelCmd,
) ngapMessage.Message {
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	m := &ngapMessage.PDUSessionResourceReleaseCommand{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		RANPagingPriority: pagingPriority, PDUSessionResourceToReleaseListRelCmd: &releaseList,
	}
	if nasPdu != nil {
		m.NASPDU = &ie.NASPDU{Value: aper.OctetString(nasPdu)}
	}
	return m
}

func BuildOverloadStart(action *ie.OverloadAction, indication *int64,
	list []ie.OverloadStartNSSAIItem,
) ngapMessage.Message {
	m := &ngapMessage.OverloadStart{}
	if action != nil {
		m.AMFOverloadResponse = &ie.OverloadResponse{Choice: action}
	}
	if indication != nil {
		m.AMFTrafficLoadReductionIndication = &ie.TrafficLoadReductionIndication{Value: *indication}
	}
	if list != nil {
		m.OverloadStartNSSAIList = &ie.OverloadStartNSSAIList{List: list}
	}
	return m
}

func BuildOverloadStop() ngapMessage.Message { return &ngapMessage.OverloadStop{} }

func marshalTransfer(value interface{ Write(*aper.PerBitData) error }) []byte {
	pd := aper.NewPerBitData(nil)
	if err := value.Write(pd); err != nil {
		return nil
	}
	return pd.Bytes()
}

func GetPDUSessionResourceSetupResponseTransfer(ipv4 string) []byte {
	return buildPDUSessionResourceSetupResponseTransfer(ipv4)
}

func GetPDUSessionResourceModifyResponseTransfer() []byte {
	m := samplePDUSessionResourceModifyResponse().(*ngapMessage.PDUSessionResourceModifyResponse)
	return append([]byte(nil), (*m.PDUSessionResourceModifyListModRes.List[0].PDUSessionResourceModifyResponseTransfer)...)
}

func GetPDUSessionResourceSetupUnsucessfulTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceSetupUnsuccessfulTransfer{Cause: normalReleaseCause()})
}

func GetPDUSessionResourceModifyUnsuccessfulTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceModifyUnsuccessfulTransfer{Cause: normalReleaseCause()})
}

func GetPDUSessionResourceModifyConfirmTransfer(qfis []int64) []byte {
	if len(qfis) == 0 {
		qfis = []int64{1}
	}
	list := &ie.QosFlowModifyConfirmList{}
	for _, qfi := range qfis {
		list.List = append(list.List, ie.QosFlowModifyConfirmItem{QosFlowIdentifier: &ie.QosFlowIdentifier{Value: qfi}})
	}
	return marshalTransfer(&ie.PDUSessionResourceModifyConfirmTransfer{
		QosFlowModifyConfirmList: list, ULNGUUPTNLInformation: upTunnel("127.0.0.1", "\x00\x00\x00\x01"),
	})
}

func GetPDUSessionResourceModifyIndicationUnsuccessfulTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceModifyIndicationUnsuccessfulTransfer{Cause: normalReleaseCause()})
}

func GetPDUSessionResourceReleaseCommandTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceReleaseCommandTransfer{Cause: normalReleaseCause()})
}

func GetPathSwitchRequestTransfer() []byte {
	m := samplePathSwitchRequest().(*ngapMessage.PathSwitchRequest)
	return append([]byte(nil), (*m.PDUSessionResourceToBeSwitchedDLList.List[0].PathSwitchRequestTransfer)...)
}

func GetPathSwitchRequestSetupFailedTransfer() []byte {
	return marshalTransfer(&ie.PathSwitchRequestSetupFailedTransfer{Cause: normalReleaseCause()})
}

func GetPDUSessionResourceModifyIndicationTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceModifyIndicationTransfer{
		DLQosFlowPerTNLInformation: qosTNL("127.0.0.1", "\x00\x00\x00\x01", 1),
	})
}

func GetPDUSessionResourceReleaseResponseTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceReleaseResponseTransfer{})
}

func GetPDUSessionResourceNotifyTransfer(qfis []int64, notificationCauses []uint64, releasedQfis []int64) []byte {
	transfer := &ie.PDUSessionResourceNotifyTransfer{}
	if len(qfis) != 0 {
		transfer.QosFlowNotifyList = &ie.QosFlowNotifyList{}
		for index, qfi := range qfis {
			cause := uint64(0)
			if index < len(notificationCauses) {
				cause = notificationCauses[index]
			}
			transfer.QosFlowNotifyList.List = append(transfer.QosFlowNotifyList.List, ie.QosFlowNotifyItem{
				QosFlowIdentifier: &ie.QosFlowIdentifier{Value: qfi},
				NotificationCause: &ie.NotificationCause{Value: aper.Enumerated(cause)},
			})
		}
	}
	if len(releasedQfis) != 0 {
		transfer.QosFlowReleasedList = &ie.QosFlowListWithCause{}
		for _, qfi := range releasedQfis {
			transfer.QosFlowReleasedList.List = append(transfer.QosFlowReleasedList.List, ie.QosFlowWithCauseItem{
				QosFlowIdentifier: &ie.QosFlowIdentifier{Value: qfi}, Cause: normalReleaseCause(),
			})
		}
	}
	return marshalTransfer(transfer)
}

func GetPDUSessionResourceNotifyReleasedTransfer() []byte {
	return marshalTransfer(&ie.PDUSessionResourceNotifyReleasedTransfer{Cause: normalReleaseCause()})
}

func GetHandoverRequestAcknowledgeTransfer() []byte {
	m := sampleHandoverRequestAcknowledge().(*ngapMessage.HandoverRequestAcknowledge)
	return append([]byte(nil), (*m.PDUSessionResourceAdmittedList.List[0].HandoverRequestAcknowledgeTransfer)...)
}

func GetHandoverResourceAllocationUnsuccessfulTransfer() []byte {
	return marshalTransfer(&ie.HandoverResourceAllocationUnsuccessfulTransfer{Cause: normalReleaseCause()})
}

func GetHandoverRequiredTransfer() []byte {
	return marshalTransfer(&ie.HandoverRequiredTransfer{})
}

func GetSourceToTargetTransparentTransfer(targetGNBID, targetCellID []byte) []byte {
	targetCell := append(append([]byte(nil), targetGNBID...), targetCellID...)
	transfer := &ie.SourceNGRANNodeToTargetNGRANNodeTransparentContainer{
		RRCContainer: &ie.RRCContainer{Value: aper.OctetString{0x00, 0x00, 0x11}},
		PDUSessionResourceInformationList: &ie.PDUSessionResourceInformationList{List: []ie.PDUSessionResourceInformationItem{{
			PDUSessionID: &ie.PDUSessionID{Value: 10},
			QosFlowInformationList: &ie.QosFlowInformationList{List: []ie.QosFlowInformationItem{{
				QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
			}}},
		}}},
		TargetCellID: &ie.NGRANCGI{Choice: &ie.NRCGI{
			PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: targetCell, BitLength: 36}},
		}},
		UEHistoryInformation: &ie.UEHistoryInformation{List: []ie.LastVisitedCellItem{{
			LastVisitedCellInformation: &ie.LastVisitedCellInformation{Choice: &ie.LastVisitedNGRANCellInformation{
				GlobalCellID: &ie.NGRANCGI{Choice: &ie.NRCGI{
					PLMNIdentity:   &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
					NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x10}, BitLength: 36}},
				}},
				CellType:           &ie.CellType{CellSize: &ie.CellSize{Value: ie.CellSizePresentVerysmall}},
				TimeUEStayedInCell: &ie.TimeUEStayedInCell{Value: 10},
			}},
		}}},
	}
	return marshalTransfer(transfer)
}

func buildPDUSessionResourceSetupResponseTransfer(ipv4 string) []byte {
	if net.ParseIP(ipv4).To4() == nil {
		ipv4 = "127.0.0.1"
	}
	return marshalTransfer(&ie.PDUSessionResourceSetupResponseTransfer{
		DLQosFlowPerTNLInformation: qosTNL(ipv4, "\x00\x00\x00\x01", 1),
	})
}

func targetRANNodeID(targetGNBID []byte) *ie.TargetID {
	return &ie.TargetID{Choice: &ie.TargetRANNodeID{
		GlobalRANNodeID: &ie.GlobalRANNodeID{Choice: &ie.GlobalGNBID{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			GNBID: &ie.GNBID{Choice: &ie.GNBIDForGNBID{Value: aper.BitString{
				Bytes: append([]byte(nil), targetGNBID...), BitLength: uint64(len(targetGNBID) * 8),
			}}},
		}},
		SelectedTAI: &ie.TAI{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			TAC:          &ie.TAC{Value: aper.OctetString{0x30, 0x33, 0x99}},
		},
	}}
}

func upTunnel(ip, teid string) *ie.UPTransportLayerInformation {
	return &ie.UPTransportLayerInformation{Choice: &ie.GTPTunnel{
		TransportLayerAddress: &ie.TransportLayerAddress{Value: aper.BitString{Bytes: net.ParseIP(ip).To4(), BitLength: 32}},
		GTPTEID:               &ie.GTPTEID{Value: aper.OctetString(teid)},
	}}
}

func qosTNL(ip, teid string, qfi int64) *ie.QosFlowPerTNLInformation {
	return &ie.QosFlowPerTNLInformation{
		UPTransportLayerInformation: upTunnel(ip, teid),
		AssociatedQosFlowList: &ie.AssociatedQosFlowList{List: []ie.AssociatedQosFlowItem{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: qfi},
		}}},
	}
}

func BuildPDUSessionResourceSetupResponseWithDC(
	pduSessionID, amfUeNgapID, ranUeNgapID int64, masterIP, masterTEID, secondaryIP, secondaryTEID string,
) ngapMessage.Message {
	transfer := &ie.PDUSessionResourceSetupResponseTransfer{DLQosFlowPerTNLInformation: qosTNL(masterIP, masterTEID, 1)}
	if secondaryIP != "" {
		transfer.AdditionalDLQosFlowPerTNLInformation = &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
			QosFlowPerTNLInformation: qosTNL(secondaryIP, secondaryTEID, 1),
		}}}
	}
	encoded, _ := ie.MarshalBinary(transfer)
	os := aper.OctetString(encoded)
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.PDUSessionResourceSetupResponse{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceSetupListSURes: &ie.PDUSessionResourceSetupListSURes{List: []ie.PDUSessionResourceSetupItemSURes{{
			PDUSessionID: &ie.PDUSessionID{Value: pduSessionID}, PDUSessionResourceSetupResponseTransfer: &os,
		}}},
	}
}

func BuildPDUSessionResourceModifyIndicationWithDC(
	pduSessionID, amfUeNgapID, ranUeNgapID int64, masterIP, masterTEID, secondaryIP, secondaryTEID string,
) ngapMessage.Message {
	transfer := &ie.PDUSessionResourceModifyIndicationTransfer{DLQosFlowPerTNLInformation: qosTNL(masterIP, masterTEID, 1)}
	if secondaryIP != "" {
		transfer.AdditionalDLQosFlowPerTNLInformation = &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
			QosFlowPerTNLInformation: qosTNL(secondaryIP, secondaryTEID, 1),
		}}}
	}
	encoded, _ := ie.MarshalBinary(transfer)
	os := aper.OctetString(encoded)
	amfID, ranID := ids(amfUeNgapID, ranUeNgapID)
	return &ngapMessage.PDUSessionResourceModifyIndication{
		AMFUENGAPID: amfID, RANUENGAPID: ranID,
		PDUSessionResourceModifyListModInd: &ie.PDUSessionResourceModifyListModInd{List: []ie.PDUSessionResourceModifyItemModInd{{
			PDUSessionID: &ie.PDUSessionID{Value: pduSessionID}, PDUSessionResourceModifyIndicationTransfer: &os,
		}}},
	}
}

func BuildPathSwitchRequestWithDC(
	pduSessionID, amfUeNgapID, ranUeNgapID int64, masterIP, masterTEID, secondaryIP, secondaryTEID string,
) ngapMessage.Message {
	m := BuildPathSwitchRequest(amfUeNgapID, ranUeNgapID).(*ngapMessage.PathSwitchRequest)
	// The path switch is reported by the secondary RAN (nGsSetup registers it with
	// TAC 0x000011), not the master RAN's TAC the base sample defaults to - override
	// it so the target TAI actually matches a TAC the AMF knows this RAN supports.
	if uliNR, ok := m.UserLocationInformation.Choice.(*ie.UserLocationInformationNR); ok && uliNR.TAI != nil {
		uliNR.TAI.TAC = &ie.TAC{Value: aper.OctetString{0x00, 0x00, 0x11}}
	}
	transfer := &ie.PathSwitchRequestTransfer{
		DLNGUUPTNLInformation: upTunnel(masterIP, masterTEID),
		QosFlowAcceptedList: &ie.QosFlowAcceptedList{List: []ie.QosFlowAcceptedItem{{
			QosFlowIdentifier: &ie.QosFlowIdentifier{Value: 1},
		}}},
	}
	if secondaryIP != "" {
		transfer.IEExtensions = &ie.ProtocolExtensionContainerPathSwitchRequestTransferExtIEs{List: []ie.PathSwitchRequestTransferExtIEs{{
			Id:          &ie.ProtocolExtensionID{Value: ie.ProtocolIEIDAdditionalDLQosFlowPerTNLInformation},
			Criticality: &ie.Criticality{Value: ie.CriticalityPresentIgnore},
			AdditionalDLQosFlowPerTNLInformation: &ie.QosFlowPerTNLInformationList{List: []ie.QosFlowPerTNLInformationItem{{
				QosFlowPerTNLInformation: qosTNL(secondaryIP, secondaryTEID, 1),
			}}},
		}}}
	}
	encoded, _ := ie.MarshalBinary(transfer)
	os := aper.OctetString(encoded)
	m.PDUSessionResourceToBeSwitchedDLList = &ie.PDUSessionResourceToBeSwitchedDLList{List: []ie.PDUSessionResourceToBeSwitchedDLItem{{
		PDUSessionID: &ie.PDUSessionID{Value: pduSessionID}, PathSwitchRequestTransfer: &os,
	}}}
	return m
}
