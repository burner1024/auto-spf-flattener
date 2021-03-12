package dns

import (
	"fmt"
	mock_dns "github.com/technowhizz/auto-spf-flattener/dns/mock_dns"
	"github.com/golang/mock/gomock"
	"testing"
)

const TestDomain = "example.com"

const TestTopSPFTXT = "v=spf1 include:_spfABC.example.com ~all"
const TestTopID = "Top1234"

const TestSubdomain = "_spfABC.example.com"
const TestSubSPFTXT = "v=spf1 ip4:1.2.3.4/5 ~all"
const TestSubID = "Sub4321"

func TestGetCurrentRecordIDs_NoChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	topRecord := TXTRecord{
		name: TestDomain,
		txt:  TestTopSPFTXT,
	}

	mockDNSAPI := mock_dns.NewMockDNSAPI(ctrl)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, "v=spf1").Return([]string{TestTopID}, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, TestTopSPFTXT).Return([]string{TestTopID}, nil)

	u := &DnsUpdater{
		Api:       mockDNSAPI,
		topDomain: TestDomain,
	}

	shouldUpdate, topRecordIDToUpdate, recordIDsToDelete := u.getCurrentRecordIDs(topRecord)

	if shouldUpdate {
		t.Error("Should not need to update")
	}
	if topRecordIDToUpdate != "" || len(recordIDsToDelete) > 0 {
		t.Error("IDs to update and delete should be empty")
	}
}

func TestGetCurrentRecordIDs_AllNew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	topRecord := TXTRecord{
		name: TestDomain,
		txt:  TestTopSPFTXT,
	}

	mockDNSAPI := mock_dns.NewMockDNSAPI(ctrl)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, "v=spf1").Return([]string{}, nil)

	u := &DnsUpdater{
		Api:       mockDNSAPI,
		topDomain: TestDomain,
	}

	shouldUpdate, topRecordIDToUpdate, recordIDsToDelete := u.getCurrentRecordIDs(topRecord)

	if !shouldUpdate {
		t.Error("Should need to update")
	}
	if topRecordIDToUpdate != "" || len(recordIDsToDelete) > 0 {
		t.Error("IDs to update and delete should be empty")
	}
}

func TestGetCurrentRecordIDs_Replace(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	newTopSPFTXT := "v=spf1 include:_spfXYZ.example.com ~all"

	topRecord := TXTRecord{
		name: TestDomain,
		txt:  newTopSPFTXT,
	}

	mockDNSAPI := mock_dns.NewMockDNSAPI(ctrl)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, "v=spf1").Return([]string{TestTopID}, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, newTopSPFTXT).Return([]string{}, nil)
	mockDNSAPI.EXPECT().GetTXTRecordContent(TestTopID).Return(TestTopSPFTXT, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestSubdomain, "v=spf1").Return([]string{TestSubID}, nil)

	u := &DnsUpdater{
		Api:       mockDNSAPI,
		topDomain: TestDomain,
	}

	shouldUpdate, topRecordIDToUpdate, recordIDsToDelete := u.getCurrentRecordIDs(topRecord)

	if !shouldUpdate {
		t.Error("Should need to update")
	}
	if topRecordIDToUpdate != TestTopID {
		t.Errorf("Should want to update top %s, instead got %s", TestTopID, topRecordIDToUpdate)
	}
	if len(recordIDsToDelete) != 1 || recordIDsToDelete[0] != TestSubID {
		t.Errorf("Should set to delete %s, instead got %v", TestSubID, recordIDsToDelete)
	}
}

func TestGetCurrentRecordIDs_MultipleTops(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// There's an additinal top record pointing to a second sub record
	secTopID := "Top5678"
	secTopSPFTXT := "v=spf1 include:_spfQRS.example.com ~all"
	secSubID := "Sub7654"

	newTopSPFTXT := "v=spf1 include:_spfXYZ.example.com ~all"

	topRecord := TXTRecord{
		name: TestDomain,
		txt:  newTopSPFTXT,
	}

	mockDNSAPI := mock_dns.NewMockDNSAPI(ctrl)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, "v=spf1").Return([]string{TestTopID, secTopID}, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestDomain, newTopSPFTXT).Return([]string{}, nil)
	mockDNSAPI.EXPECT().GetTXTRecordContent(TestTopID).Return(TestTopSPFTXT, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords(TestSubdomain, "v=spf1").Return([]string{TestSubID}, nil)
	mockDNSAPI.EXPECT().GetTXTRecordContent(secTopID).Return(secTopSPFTXT, nil)
	mockDNSAPI.EXPECT().FilterTXTRecords("_spfQRS.example.com", "v=spf1").Return([]string{secSubID}, nil)

	u := &DnsUpdater{
		Api:       mockDNSAPI,
		topDomain: TestDomain,
	}

	shouldUpdate, topRecordIDToUpdate, recordIDsToDelete := u.getCurrentRecordIDs(topRecord)

	if !shouldUpdate {
		t.Error("Should need to update")
	}
	if topRecordIDToUpdate != TestTopID {
		t.Errorf("Should want to update top %s, instead got %s", TestTopID, topRecordIDToUpdate)
	}
	expected := fmt.Sprintf("%v", []string{TestSubID, secTopID, secSubID})
	if fmt.Sprintf("%v", recordIDsToDelete) != expected {
		t.Errorf("Should set to delete three ids, instead got %v", recordIDsToDelete)
	}
}
