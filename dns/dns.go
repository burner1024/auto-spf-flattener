package dns

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	spf "github.com/lordbyron/auto-spf-flattener/spf"
)

type DNSAPI interface {
	WriteTXTRecord(string, string) (string, error)
	DeleteTXTRecordByName(string) error
	DeleteTXTRecord(string) error
}

// simple printer implements DNSAPI
type DNSPrinter struct{}

func (p *DNSPrinter) WriteTXTRecord(name, txt string) (string, error) {
	fmt.Printf("API->WriteTXTRecord(%s, `%s`)\n", name, txt)
	return name, nil
}

func (p *DNSPrinter) DeleteTXTRecordByName(name string) error {
	fmt.Printf("API->DeleteTXTRecordByName(%s)\n", name)
	return nil
}

func (p *DNSPrinter) DeleteTXTRecord(id string) error {
	fmt.Printf("API->DeleteTXTRecord(%s)\n", id)
	return nil
}

type DNSUpdaterIface interface {
	Update(*spf.SPF) error
}

type DnsUpdater struct {
	Api                DNSAPI
	topDomain          string
	spfSubdomainPrefix string
	flatMemo           string
	idMemo             []string
}

type TXTRecord struct {
	name string
	txt  string
}

func NewDNSUpdater(api DNSAPI, topDomain, spfSubdomainPrefix string) *DnsUpdater {
	return &DnsUpdater{
		Api:                api,
		topDomain:          topDomain,
		spfSubdomainPrefix: spfSubdomainPrefix,
		flatMemo:           "",
	}
}

func (u *DnsUpdater) needsUpdate(record *spf.SPF) bool {
	serialized := fmt.Sprintf("%v", record)
	sum := sha1.Sum([]byte(serialized))
	hash := string(sum[:])
	if u.flatMemo == hash {
		return false
	} else {
		u.flatMemo = hash
		return true
	}
}

// Input is the preferred SPF regardless of DNS lookups and response size
func (u *DnsUpdater) Update(ideal *spf.SPF) error {

	flat, err := ideal.Flatten()
	if err != nil {
		return err
	}

	// if no update is needed, skip it
	if !u.needsUpdate(flat) {
		return nil
	}

	var records []TXTRecord

	if flat.LookupCount <= 10 {
		// No need for flattening
		records = []TXTRecord{TXTRecord{
			name: u.topDomain,
			txt:  ideal.AsTXTRecord(),
		}}
	} else {
		// Need to split it up
		splits, err := flat.Split()
		if err != nil {
			return err
		}
		records = u.makeRecords(splits)
	}

	if len(records) > 0 {
		u.updateDNS(records)
	}

	return nil
}

func (u *DnsUpdater) makeRecords(splits []*spf.SPF) []TXTRecord {
	records := []TXTRecord{}

	topSPF := spf.NewSPF()
	topSPF.AllRune = splits[0].AllRune

	for _, split := range splits {
		txt := split.AsTXTRecord()
		sig := hash(txt)
		subdomain := u.spfSubdomainPrefix + sig
		record := TXTRecord{
			name: subdomain,
			txt:  txt,
		}
		records = append(records, record)
		topSPF.Include = append(topSPF.Include, subdomain+"."+u.topDomain)
	}
	records = append(records, TXTRecord{
		name: u.topDomain,
		txt:  topSPF.AsTXTRecord(),
	})
	return records
}

func hash(txt string) string {
	sum := sha1.Sum([]byte(txt))
	return hex.EncodeToString(sum[0:3])
}

func (u *DnsUpdater) updateDNS(records []TXTRecord) error {
	// Need to add new records as well as delete the old ones
	// 1. Create new subdomain records
	// 2. Add new top level record (there will be a duplicate, possibly invalid)
	// 3. Delete old top level record
	// 4. Delete old subdomain records

	newIDs := []string{}
	// 1. and 2.
	for _, record := range records {
		id, err := u.Api.WriteTXTRecord(record.name, record.txt)
		if err != nil {
			return err
		}
		// prepend so top record, which is last in the inputs, is first in the output
		newIDs = append([]string{id}, newIDs...)
	}

	// 3. and 4.
	for _, oldID := range u.idMemo {
		err := u.Api.DeleteTXTRecord(oldID)
		if err != nil {
			return err
		}
	}

	u.idMemo = newIDs
	return nil
}
