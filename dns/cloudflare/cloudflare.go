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
	UpdateDNSRecord(string, string, cf.DNSRecord) error
	DeleteDNSRecord(string, string) error
	DNSRecords(string, cf.DNSRecord) ([]cf.DNSRecord, error)
	DNSRecord(string, string) (cf.DNSRecord, error)
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
type CloudflareAPIClient struct {
	ZoneID string
	Api    CloudflareAPI
}

func NewCloudflareAPIClient(zoneName string) *CloudflareAPIClient {
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
	return &CloudflareAPIClient{
		ZoneID: zones[0].ID,
		Api:    api,
	}
}

// Find a set of IDs that match the text filter
func (c *CloudflareAPIClient) FilterTXTRecords(name, filter string) ([]string, error) {
	rr := cf.DNSRecord{
		Type: "TXT",
		Name: name,
	}
	records, err := c.Api.DNSRecords(c.ZoneID, rr)
	if err != nil {
		return []string{}, err
	}
	results := []string{}
	for _, record := range records {
		if strings.Contains(record.Content, filter) {
			results = append(results, record.ID)
		}
	}
	return results, nil
}

func (c *CloudflareAPIClient) GetTXTRecordContent(id string) (string, error) {
	if record, err := c.Api.DNSRecord(c.ZoneID, id); err != nil {
		return "", err
	} else {
		return record.Content, nil
	}
}

func (c *CloudflareAPIClient) WriteTXTRecord(name, txt string) (string, error) {
	rr := cf.DNSRecord{
		Type:    "TXT",
		Name:    name,
		Content: txt,
	}
	response, err := c.Api.CreateDNSRecord(c.ZoneID, rr)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", errors.New(strings.Join(response.Errors, " -- "))
	}
	id := response.Result.ID
	return id, err
}

// Update does not change the ID
func (c *CloudflareAPIClient) UpdateTXTRecord(id, name, txt string) (string, error) {
	rr := cf.DNSRecord{
		Type:    "TXT",
		Name:    name,
		Content: txt,
	}
	err := c.Api.UpdateDNSRecord(c.ZoneID, id, rr)
	if err != nil {
		return "", err
	}
	return id, err
}

func (c *CloudflareAPIClient) DeleteTXTRecord(id string) error {
	return c.Api.DeleteDNSRecord(c.ZoneID, id)
}
