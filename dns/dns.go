package dns

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	spf "github.com/envoy/auto-spf-flattener/spf"
)

type DNSAPI interface {
	FilterTXTRecords(string, string) ([]string, error)
	GetTXTRecordContent(string) (string, error)
	WriteTXTRecord(string, string) (string, error)
	UpdateTXTRecord(string, string, string) (string, error)
	DeleteTXTRecord(string) error
}

// simple printer implements DNSAPI
type DNSPrinter struct{}

func (p *DNSPrinter) FilterTXTRecords(name, filter string) ([]string, error) {
	fmt.Printf("API->FilterTXTRecords(%s, %s)\n", name, filter)
	return []string{}, nil
}

func (p *DNSPrinter) GetTXTRecordContent(id string) (string, error) {
	fmt.Printf("API->GetTXTRecordContent(%s)\n", id)
	return id, nil
}

func (p *DNSPrinter) WriteTXTRecord(name, txt string) (string, error) {
	fmt.Printf("API->WriteTXTRecord(%s, `%s`)\n", name, txt)
	return name, nil
}

func (p *DNSPrinter) UpdateTXTRecord(id, name, txt string) (string, error) {
	fmt.Printf("API->UpdateTXTRecord(%s, %s, `%s`)\n", id, name, txt)
	return name, nil
}

func (p *DNSPrinter) DeleteTXTRecord(id string) error {
	fmt.Printf("API->DeleteTXTRecord(%s)\n", id)
	return nil
}

type DnsUpdater struct {
	Api                DNSAPI
	topDomain          string
	spfSubdomainPrefix string
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
	}
}

// Input is the preferred SPF regardless of DNS lookups and response size
func (u *DnsUpdater) Update(ideal *spf.SPF, dryRun bool) error {

	flat, err := ideal.Flatten()
	if err != nil {
		return err
	}

	records := []TXTRecord{}
	var topRecord TXTRecord

	if flat.LookupCount <= 10 {
		// No need for flattening
		// var records remains empty
		topRecord = TXTRecord{
			name: u.topDomain,
			txt:  ideal.AsTXTRecord(),
		}
	} else {
		// Need to split it up
		splits, err := flat.Split()
		if err != nil {
			return err
		}
		records, topRecord = u.makeRecords(splits)
	}

	shouldUpdate, topRecordIDToUpdate, recordIDsToDelete := u.getCurrentRecordIDs(topRecord)
	if !shouldUpdate {
		// all done here
		return nil
	}

	return u.updateDNS(topRecordIDToUpdate, topRecord, records, recordIDsToDelete, dryRun)
}

// Returns a slice of subdomain records and one top-level record, which
// references them.
func (u *DnsUpdater) makeRecords(splits []*spf.SPF) ([]TXTRecord, TXTRecord) {
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
	return records, TXTRecord{
		name: u.topDomain,
		txt:  topSPF.AsTXTRecord(),
	}
}

func hash(txt string) string {
	sum := sha1.Sum([]byte(txt))
	return hex.EncodeToString(sum[0:3])
}

func (u *DnsUpdater) updateDNS(topRecordIDToUpdate string, topRecord TXTRecord, newRecords []TXTRecord, recordIDsToDelete []string, dryRun bool) error {
	// Need to add new records as well as delete the old ones
	// 1. Create new subdomain records
	// 2. Update or create top record
	// 3. Delete any old top or sub records

	// Always print what we're modifying
	printer := &DNSPrinter{}

	// 1.
	for _, record := range newRecords {
		printer.WriteTXTRecord(record.name, record.txt)
		if !dryRun {
			_, err := u.Api.WriteTXTRecord(record.name, record.txt)
			if err != nil {
				return err
			}
		}
	}

	// 2.
	if topRecordIDToUpdate == "" {
		printer.WriteTXTRecord(topRecord.name, topRecord.txt)
		if !dryRun {
			_, err := u.Api.WriteTXTRecord(topRecord.name, topRecord.txt)
			if err != nil {
				return err
			}
		}
	} else {
		printer.UpdateTXTRecord(topRecordIDToUpdate, topRecord.name, topRecord.txt)
		if !dryRun {
			_, err := u.Api.UpdateTXTRecord(topRecordIDToUpdate, topRecord.name, topRecord.txt)
			if err != nil {
				return err
			}
		}
	}

	// 3.
	for _, oldID := range recordIDsToDelete {
		printer.DeleteTXTRecord(oldID)
		if !dryRun {
			err := u.Api.DeleteTXTRecord(oldID)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Look at the current DNS settings and figure out what needs to change
func (u *DnsUpdater) getCurrentRecordIDs(topRecord TXTRecord) (bool, string, []string) {
	var topRecordIDToUpdate string
	var recordIDsToDelete []string = []string{}

	allTopRecordIDs, _ := u.Api.FilterTXTRecords(u.topDomain, "v=spf1")
	if len(allTopRecordIDs) == 0 {
		// no top record found, can't really do anything
		// still need to add new DNS records
		return true, topRecordIDToUpdate, recordIDsToDelete
	}

	goodTopRecordIDs, _ := u.Api.FilterTXTRecords(u.topDomain, topRecord.txt)
	var goodTopRecordID string
	if len(goodTopRecordIDs) > 0 {
		// It's possible that multiple match. Let the others get deleted.
		goodTopRecordID = goodTopRecordIDs[0]
	}

	if len(allTopRecordIDs) == 1 && allTopRecordIDs[0] == goodTopRecordID {
		// Everything is correct, so do nothing!
		return false, topRecordIDToUpdate, recordIDsToDelete
	}

	for _, topRecordID := range allTopRecordIDs {
		if topRecordIDToUpdate == "" {
			topRecordIDToUpdate = topRecordID
		} else {
			recordIDsToDelete = append(recordIDsToDelete, topRecordID)
		}
		if content, err := u.Api.GetTXTRecordContent(topRecordID); err == nil {
			topSPF := spf.NewSPF()
			if topSPF.Parse(content) == nil {
				for _, include := range topSPF.Include {
					subRecordIDs, _ := u.Api.FilterTXTRecords(include, "v=spf1")
					recordIDsToDelete = append(recordIDsToDelete, subRecordIDs...)
				}
			}
		}
	}
	return true, topRecordIDToUpdate, recordIDsToDelete
}
