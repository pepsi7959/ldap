package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type Attribute struct {
	attrType string
	attrVals []string
}

func (p *Attribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, p.attrType, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range p.attrVals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

type AddRequest struct {
	dn            string
	addAttributes []Attribute
	controls      []Control
}

func (r *AddRequest) Add(attrType string, attrVals []string) {
	r.addAttributes = append(r.addAttributes, Attribute{attrType: attrType, attrVals: attrVals})
}

func (r AddRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.dn, "DN"))
	adds := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Adds")
	for _, attribute := range r.addAttributes {
		adds.AppendChild(attribute.encode())
	}
	request.AppendChild(adds)
	// encode controls
	if len(r.controls) > 0 {
		request.AppendChild(encodeControls(r.controls))
	}
	return request
}

func NewAddRequest(
	dn string,
	controls []Control,
) *AddRequest {
	return &AddRequest{
		dn:       dn,
		controls: controls,
	}
}

func (l *Conn) Add(addRequest *AddRequest) error {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(addRequest.encode())

	l.Debug.PrintPacket(packet)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	if channel == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	l.Debug.Printf("%d: waiting for response", messageID)
	packet = <-channel
	l.Debug.Printf("%d: got response %p", messageID, packet)
	if packet == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationAddResponse {
		resultCode, resultDescription, matchedDn := getLDAPResultCode(packet)
		if resultCode != 0 {
			return NewError(resultCode, errors.New(resultDescription), matchedDn)
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}

	l.Debug.Printf("%d: returning", messageID)
	return nil
}
