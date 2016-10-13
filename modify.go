// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// File contains Modify functionality
//
// https://tools.ietf.org/html/rfc4511
//
// ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//      object          LDAPDN,
//      changes         SEQUENCE OF change SEQUENCE {
//           operation       ENUMERATED {
//                add     (0),
//                delete  (1),
//                replace (2),
//                ...  },
//           modification    PartialAttribute } }
//
// PartialAttribute ::= SEQUENCE {
//      type       AttributeDescription,
//      vals       SET OF value AttributeValue }
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

const (
	AddAttribute     = 0
	DeleteAttribute  = 1
	ReplaceAttribute = 2
)

type PartialAttribute struct {
	op       int
	attrType string
	attrVals []string
}

func (p *PartialAttribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, p.attrType, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range p.attrVals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

type ModifyRequest struct {
	dn         string
	attributes []PartialAttribute
	controls   []Control
}

func (m *ModifyRequest) Add(attrType string, attrVals []string) {
	m.attributes = append(m.attributes, PartialAttribute{op: AddAttribute, attrType: attrType, attrVals: attrVals})
}

func (m *ModifyRequest) Delete(attrType string, attrVals []string) {
	m.attributes = append(m.attributes, PartialAttribute{op: DeleteAttribute, attrType: attrType, attrVals: attrVals})
}

func (m *ModifyRequest) Replace(attrType string, attrVals []string) {
	m.attributes = append(m.attributes, PartialAttribute{op: ReplaceAttribute, attrType: attrType, attrVals: attrVals})
}

func (m ModifyRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyRequest, nil, "Modify Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.dn, "DN"))
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	for _, attribute := range m.attributes {
		change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
		change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(attribute.op), "Operation"))
		change.AppendChild(attribute.encode())
		changes.AppendChild(change)
	}
	request.AppendChild(changes)

	return request
}

func NewModifyRequest(
	dn string,
	controls []Control,
) *ModifyRequest {
	return &ModifyRequest{
		dn:       dn,
		controls: controls,
	}
}

func (l *Conn) Modify(r *ModifyRequest) error {
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

	if packet.Children[1].Tag == ApplicationModifyResponse {
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
