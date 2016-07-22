// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// File contains Modify functionality
//
// https://tools.ietf.org/html/rfc4511
//
// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//             entry           LDAPDN,
//             newrdn          RelativeLDAPDN,
//             deleteoldrdn    BOOLEAN,
//             newSuperior     [0] LDAPDN OPTIONAL }
//
// RelativeLDAPDN ::= LDAPString -- Constrained to <name-component>
//                          -- [RFC4514]
//
// AttributeDescription ::= LDAPString
//                         -- Constrained to <attributedescription>
//                         -- [RFC4512]
//
// AttributeValue ::= OCTET STRING
//

package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type ModifyDNRequest struct {
	dn           string
	newrdn       string
	deleteoldrdn bool
	newSuperior  string
	controls     []Control
}

func (m ModifyDNRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyDNRequest, nil, "Modify DN Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.dn, "DN"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.newrdn, "NewRDN"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, m.deleteoldrdn, "DeleteOldRDN"))
	if m.newSuperior != "" {
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.newSuperior, "NewSuperior"))
	}

	return request
}

func NewModifyDNRequest(
	dn string,
	newrdn string,
	deleteoldrdn bool,
	newSuperior string,
	controls []Control,
) *ModifyDNRequest {
	return &ModifyDNRequest{
		dn:           dn,
		newrdn:       newrdn,
		deleteoldrdn: deleteoldrdn,
		newSuperior:  newSuperior,
		controls:     controls,
	}
}

func (l *Conn) ModifyDn(r *ModifyDNRequest) error {
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

	if packet.Children[1].Tag == ApplicationModifyDNResponse {
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
