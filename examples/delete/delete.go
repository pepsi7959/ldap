// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
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

	log.Printf("--> Add")
	add := ldap.NewAddRequest("commit=21,cn=hardstates,cn=raft")
	add.Add("commit", []string{"21"})
	add.Add("term", []string{"100"})
	add.Add("vote", []string{"100"})
	add.Add("objectClass", []string{"raftStateObject"})
	if err := l.Add(add); err != nil {
		log.Fatalf("ERROR: %s\n", err.Error())
	}

	log.Printf("--> Delete")
	del := ldap.NewDeleteRequest("commit=21,cn=hardstates,cn=raft")
	if err := l.Delete(del); err != nil {
		log.Fatalf("Error: %s\n", err.Error())
	}

}
