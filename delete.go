package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type DeleteRequest struct {
	dn string
}

func (r DeleteRequest) encode() *ber.Packet {
	request := ber.NewString(ber.ClassApplication, ber.TypePrimitive, ApplicationDelRequest, r.dn, "DN")
	return request
}

func NewDeleteRequest(dn string) *DeleteRequest {
	return &DeleteRequest{
		dn: dn,
	}
}

func (l *Conn) Delete(deleteRequest *DeleteRequest) error {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(deleteRequest.encode())

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

	if packet.Children[1].Tag == ApplicationDelResponse {
		resultCode, resultDescription, verbose := getLDAPResultCode(packet)
		if resultCode != 0 {
			return NewError(resultCode, errors.New(resultDescription), verbose)
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}

	l.Debug.Printf("%d: returning", messageID)
	return nil
}
