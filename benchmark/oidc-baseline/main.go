package main

import (
	"flag"
	broker "secure-sso/Broker"
	idp "secure-sso/IdP"
	rp "secure-sso/RP"
)

func main() {
	name := flag.String("name", "idp", "Enter the server name you want to start: [usage] idp/broker/rp")
	register := flag.Bool("register", false, "Auto-register client on startup (only for rp and broker)")
	flag.Parse()

	switch *name {
	case "idp":
		idp.StartIdpServer()
	case "broker":
		broker.StartBrokerServer(*register)
	case "rp":
		rp.StartRpServer(*register)
	case "test_register":
		rp.BenchmarkRegister()
	}
}
