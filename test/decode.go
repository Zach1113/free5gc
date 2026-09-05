package test

import (
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
)

// GetNasPdu extracts and decodes the NAS PDU carried by a DownlinkNASTransport.
// The new ngap API exposes the IE as a field, so there is no need to walk the
// ProtocolIEs list looking for ProtocolIEIDNASPDU any more.
func GetNasPdu(ue *RanUeContext, msg *ngapMessage.DownlinkNASTransport) nasMessage.Message {
	if msg == nil || msg.NASPDU == nil {
		return nil
	}

	pkg := []byte(msg.NASPDU.Value)
	m, err := NASDecode(ue, nasMessage.GetSecHdrType(pkg), pkg)
	if err != nil {
		return nil
	}
	return m
}
