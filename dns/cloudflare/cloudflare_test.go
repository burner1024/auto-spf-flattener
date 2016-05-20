package cloudflare

import (
	cf "github.com/cloudflare/cloudflare-go"
	"github.com/golang/mock/gomock"
	mock_dns "github.com/lordbyron/auto-spf-flattener/dns/cloudflare/mock_cloudflare"
	"testing"
)

const TestZoneName = "my_zone"
const TestZoneID = "zone1234"
const TestDomain = "_spf.example.com"
const TestSPFTXT = "v=spf1 ip4:1.2.3.4/5 ~all"
const TestRecordID = "TXT4321"

func TestWriteTXT(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	expectedRr := cf.DNSRecord{
		Type:    "TXT",
		Name:    TestDomain,
		Content: TestSPFTXT,
	}
	response := &cf.DNSRecordResponse{
		Response: cf.Response{
			Success: true,
		},
		Result: cf.DNSRecord{
			ID: TestRecordID,
		},
	}

	mockCloudflare := mock_dns.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().CreateDNSRecord(TestZoneID, expectedRr).Return(response, nil)

	cfu := &CloudflareUpdater{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	id, err := cfu.WriteTXTRecord(TestDomain, TestSPFTXT)
	if err != nil {
		t.Errorf("Error writing TXT record: %s", err)
	}
	if id != TestRecordID {
		t.Errorf("Wrong id returned during create: `%s`", id)
	}
}

func TestDeleteTXTRecordByName(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	expectedRr := cf.DNSRecord{
		Type: "TXT",
		Name: TestDomain,
	}
	response := []cf.DNSRecord{cf.DNSRecord{
		ID:      TestRecordID,
		Type:    "TXT",
		Name:    TestDomain,
		Content: TestSPFTXT,
	}}

	mockCloudflare := mock_dns.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().DNSRecords(TestZoneID, expectedRr).Return(response, nil)
	mockCloudflare.EXPECT().DeleteDNSRecord(TestZoneID, TestRecordID).Return(nil)

	cfu := &CloudflareUpdater{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	err := cfu.DeleteTXTRecordByName(TestDomain)
	if err != nil {
		t.Errorf("Error deleting TXT record: %s", err)
	}
}
