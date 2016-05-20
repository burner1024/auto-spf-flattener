package cloudflare

import (
	"errors"
	cf "github.com/cloudflare/cloudflare-go"
	"os"
	"strings"
)

// Allows me to mock the underlying struct in tests
// cf.API implements this interface
type CloudflareAPI interface {
	CreateDNSRecord(string, cf.DNSRecord) (*cf.DNSRecordResponse, error)
	DeleteDNSRecord(string, string) error
	DNSRecords(string, cf.DNSRecord) ([]cf.DNSRecord, error)
}

// implements CloudflareAPI while wrapping the actual CF API object
//type CloudflareAPIPrinter struct{}
//
//func (cfw *CloudflareAPIPrinter) CreateDNSRecord(zoneID string, rr cf.DNSRecord) (*cf.DNSRecordResponse, error) {
//	fmt.Printf("API->CreateDNSRecord(%s, %s `%s`)\n", zoneID, rr.Name, rr.Content)
//	return &cf.DNSRecordResponse{
//		Response: cf.Response{
//			Success: true,
//		},
//	}, nil
//}
//
//func (cfw *CloudflareAPIPrinter) DNSRecords(zoneID string, rr cf.DNSRecord) ([]cf.DNSRecord, error) {
//	fmt.Printf("API->DNSRecords(%s, %s %s)\n", zoneID, rr.Type, rr.Name)
//	return []cf.DNSRecord{
//		cf.DNSRecord{
//			ID:   "txt-recordID",
//			Type: "TXT",
//		},
//	}, nil
//}
//
//func (cfw *CloudflareAPIPrinter) DeleteDNSRecord(zoneID, recordID string) error {
//	fmt.Printf("API->DeleteDNSRecord(%s, %s)\n", zoneID, recordID)
//	return nil
//}

// Implements dns.DNSAPI
type CloudflareUpdater struct {
	ZoneID string
	Api    CloudflareAPI
}

func NewCloudflareUpdater(zoneName string) *CloudflareUpdater {
	api, newErr := cf.New(os.Getenv("CF_API_KEY"), os.Getenv("CF_API_EMAIL"))
	if newErr != nil {
		panic(newErr)
	}
	zones, zonesErr := api.ListZones(zoneName)
	if zonesErr != nil {
		panic(zonesErr)
	}
	if len(zones) != 1 {
		panic("didn't find exactly one zone named " + zoneName)
	}
	return &CloudflareUpdater{
		ZoneID: zones[0].ID,
		Api:    api,
	}
}

func (cfu *CloudflareUpdater) WriteTXTRecord(name, txt string) (string, error) {
	rr := cf.DNSRecord{
		Type:    "TXT",
		Name:    name,
		Content: txt,
	}
	response, err := cfu.Api.CreateDNSRecord(cfu.ZoneID, rr)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", errors.New(strings.Join(response.Errors, " -- "))
	}
	id := response.Result.ID
	return id, err
}

func (cfu *CloudflareUpdater) DeleteTXTRecordByName(name string) error {
	rr := cf.DNSRecord{
		Type: "TXT",
		Name: name,
	}
	records, err := cfu.Api.DNSRecords(cfu.ZoneID, rr)
	if err != nil {
		return err
	}
	if len(records) != 1 {
		return errors.New("didn't find exactly one txt record named " + name)
	}
	if records[0].Type != "TXT" {
		return errors.New("Cannot delete DNS record because type is not TXT: " + records[0].Type)
	}
	id := records[0].ID
	return cfu.DeleteTXTRecord(id)
}

func (cfu *CloudflareUpdater) DeleteTXTRecord(id string) error {
	return cfu.Api.DeleteDNSRecord(cfu.ZoneID, id)
}
