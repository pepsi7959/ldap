package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type DeleteRequest struct {
	dn       string
	controls []Control
}

type DeleteResponse struct {
	Controls []Control
}

func (r DeleteRequest) encode() *ber.Packet {
	request := ber.NewString(ber.ClassApplication, ber.TypePrimitive, ApplicationDelRequest, r.dn, "DN")
	return request
}

func NewDeleteRequest(dn string, controls []Control) *DeleteRequest {
	return &DeleteRequest{
		dn:       dn,
		controls: controls,
	}
}

func (l *Conn) Delete(r *DeleteRequest) (*DeleteResponse, error) {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(r.encode())

	// encode search controls
	if len(r.controls) > 0 {
		packet.AppendChild(encodeControls(r.controls))
	}

	l.Debug.PrintPacket(packet)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	if channel == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	l.Debug.Printf("%d: waiting for response", messageID)
	packet = <-channel
	l.Debug.Printf("%d: got response %p", messageID, packet)
	if packet == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	result := &DeleteResponse{
		Controls: make([]Control, 0),
	}

	if packet.Children[1].Tag == ApplicationDelResponse {
		resultCode, resultDescription, matchedDn := getLDAPResultCode(packet)
		if resultCode != 0 {
			return result, NewError(resultCode, errors.New(resultDescription), matchedDn)
		}

		if len(packet.Children) == 3 {
			for _, child := range packet.Children[2].Children {
				result.Controls = append(result.Controls, DecodeControl(child))
			}
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}

	l.Debug.Printf("%d: returning", messageID)
	return result, nil
}
