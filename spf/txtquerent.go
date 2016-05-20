package spf

import (
	"net"
)

type TXTQuerent interface {
	Query(string) ([]string, error)
}

type SimpleTXTQuerent struct {
}

func (q SimpleTXTQuerent) Query(name string) ([]string, error) {
	return net.LookupTXT(name)
}
