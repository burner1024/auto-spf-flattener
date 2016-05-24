package cloudflare

import (
	cf "github.com/cloudflare/cloudflare-go"
	mock_cloudflare "github.com/envoy/auto-spf-flattener/dns/cloudflare/mock_cloudflare"
	"github.com/golang/mock/gomock"
	"testing"
)

const TestZoneName = "my_zone"
const TestZoneID = "zone1234"
const TestDomain = "_spf.example.com"
const TestSPFTXT = "v=spf1 ip4:1.2.3.4/5 ~all"
const TestRecordID = "TXT4321"

func TestFilterTXTRecords(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	expectedRr := cf.DNSRecord{
		Type: "TXT",
		Name: TestDomain,
	}
	response := []cf.DNSRecord{
		cf.DNSRecord{
			ID:      TestRecordID,
			Content: TestSPFTXT,
		},
		cf.DNSRecord{
			ID:      "bad_id",
			Content: "nothing to see here",
		},
	}

	mockCloudflare := mock_cloudflare.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().DNSRecords(TestZoneID, expectedRr).Return(response, nil)

	client := &CloudflareAPIClient{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	ids, err := client.FilterTXTRecords(TestDomain, "spf1")
	if err != nil {
		t.Errorf("Error writing TXT record: %s", err)
	}
	if len(ids) != 1 {
		t.Errorf("Wrong number of records returned: %d", len(ids))
	}
	if ids[0] != TestRecordID {
		t.Errorf("Wrong record ID returned: %s", ids[0])
	}
}

func TestGetTXTRecordContent(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	response := cf.DNSRecord{
		Type:    "TXT",
		Name:    TestDomain,
		Content: TestSPFTXT,
	}

	mockCloudflare := mock_cloudflare.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().DNSRecord(TestZoneID, TestRecordID).Return(response, nil)

	client := &CloudflareAPIClient{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	content, err := client.GetTXTRecordContent(TestRecordID)
	if err != nil {
		t.Errorf("Error getting TXT record: %s", err)
	}
	if content != TestSPFTXT {
		t.Errorf("Wrong content returned during fetch: `%s`", content)
	}
}

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

	mockCloudflare := mock_cloudflare.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().CreateDNSRecord(TestZoneID, expectedRr).Return(response, nil)

	client := &CloudflareAPIClient{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	id, err := client.WriteTXTRecord(TestDomain, TestSPFTXT)
	if err != nil {
		t.Errorf("Error writing TXT record: %s", err)
	}
	if id != TestRecordID {
		t.Errorf("Wrong id returned during create: `%s`", id)
	}
}

func TestUpdateTXTRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	expectedRr := cf.DNSRecord{
		Type:    "TXT",
		Name:    TestDomain,
		Content: TestSPFTXT,
	}

	mockCloudflare := mock_cloudflare.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().UpdateDNSRecord(TestZoneID, TestRecordID, expectedRr).Return(nil)

	client := &CloudflareAPIClient{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	id, err := client.UpdateTXTRecord(TestRecordID, TestDomain, TestSPFTXT)
	if err != nil {
		t.Errorf("Error deleting TXT record: %s", err)
	}
	if id != TestRecordID {
		t.Errorf("Wrong id returned: %s", id)
	}
}

func TestDeleteTXTRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCloudflare := mock_cloudflare.NewMockCloudflareAPI(ctrl)
	mockCloudflare.EXPECT().DeleteDNSRecord(TestZoneID, TestRecordID).Return(nil)

	client := &CloudflareAPIClient{
		ZoneID: TestZoneID,
		Api:    mockCloudflare,
	}

	err := client.DeleteTXTRecord(TestRecordID)
	if err != nil {
		t.Errorf("Error deleting TXT record: %s", err)
	}
}
