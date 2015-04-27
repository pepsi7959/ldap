// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/phoorichet/ldap"
)

var (
	LdapServer string = "localhost"
	LdapPort   uint16 = 389
	BaseDN     string = "cn=raft"
	BindDN     string = "cn=raft"
	BindPW     string = "secret"
	Filter     string = "(objectClass=*)"
)

func search(l *ldap.Conn, filter string, attributes []string) (*ldap.Entry, error) {
	search := ldap.NewSearchRequest(
		BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := l.Search(search)
	if err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
		return nil, err
	}

	log.Printf("Search: %s -> num of entries = %d\n", search.Filter, len(sr.Entries))
	if len(sr.Entries) == 0 {
		return nil, ldap.NewError(ldap.ErrorDebugging, errors.New(fmt.Sprintf("no entries found for: %s", filter)))
	}
	return sr.Entries[0], nil
}

func main() {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", LdapServer, LdapPort))
	if err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}
	defer l.Close()
	l.Debug = true

	l.Bind(BindDN, BindPW)

	// log.Printf("The Search for * ... %s\n", Filter)
	// entry, err := search(l, Filter, []string{})
	// if err != nil {
	// 	log.Fatal("could not get entry")
	// }
	// entry.PrettyPrint(0)

	log.Printf("-----add----")
	add := ldap.NewAddRequest("cn=test,cn=raft")
	// add.Add("cn", []string{"test"})
	// add.Add("commit", []string{"100"})
	// add.Add("term", []string{"100"})
	// add.Add("vote", []string{"100"})
	add.Add("objectClass", []string{"raftGeneralObject"})
	if err := l.Add(add); err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}

}
