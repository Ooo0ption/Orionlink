// Single binary for OrionLink: -name selects which server role to run.
package main

import (
	"flag"
	"fmt"

	broker "secure-sso/Broker"
	idp "secure-sso/IdP"
	rp "secure-sso/RP"
)

// main starts one server role, selected with -name.
func main() {
	name := flag.String("name", "idp", "server: idp | broker | rp")
	flag.Parse()

	switch *name {
	case "idp":
		idp.StartIdpServer()
	case "broker":
		broker.StartBrokerServer()
	case "rp":
		rp.StartRpServer()
	default:
		fmt.Printf("unknown -name=%q (expected idp | broker | rp)\n", *name)
	}
}
