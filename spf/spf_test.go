package spf

import (
	"fmt"
	"testing"
)

func TestAppendSPF(t *testing.T) {
	r1 := &SPF{
		V:       "spf1",
		Ip4:     []string{"1.2.3.4/5", "6.7.8.9/0"},
		Ip6:     []string{"12:34:56::/78"},
		Include: []string{},
		AllRune: '?',
	}
	r2 := &SPF{
		V:       "spf1",
		Ip4:     []string{"5.4.3.2/1"},
		Ip6:     []string{"12:34:56::/78", "87:65:43::/21"}, // duplicate
		Include: []string{"_spf.example.com", "_spf2.example.com"},
		AllRune: '-',
	}
	r1.Append(r2)

	ip4exp := []string{"1.2.3.4/5", "6.7.8.9/0", "5.4.3.2/1"}
	for _, ip4 := range ip4exp {
		if !strInSlice(ip4, r1.Ip4) {
			t.Errorf("Failed to find string %s in r1.ip4", ip4)
		}
	}
	ip6exp := []string{"12:34:56::/78", "87:65:43::/21"}
	for _, ip6 := range ip6exp {
		if !strInSlice(ip6, r1.Ip6) {
			t.Errorf("Failed to find string %s in r1.ip6", ip6)
		}
	}
	incexp := []string{"_spf.example.com", "_spf2.example.com"}
	for _, inc := range incexp {
		if !strInSlice(inc, r1.Include) {
			t.Errorf("Failed to find string %s in r1.inc", inc)
		}
	}
	if r1.AllRune != '-' {
		t.Errorf("Failed to set allRune: %c", r1.AllRune)
	}
}

func TestSplit(t *testing.T) {
	r1 := NewSPF()
	for i := 0; i < 100; i++ {
		r1.Ip4 = append(r1.Ip4, fmt.Sprintf("%d.%d.%d.%d/%d", i, i, i, i, i))
	}
	spfs, err := r1.Split()
	if err != nil {
		t.Errorf("Error during split: %s", err)
	}
	if len(spfs) != (100/19 + 1) {
		t.Errorf("Wrong number of SPF records returned: %d", len(spfs))
	}
	if len(r1.Ip4) < 100 {
		t.Error("Split should not have modified original record")
	}
}

func TestSplitWithIncludes(t *testing.T) {
	r1 := &SPF{
		V:       "spf1",
		Ip4:     []string{"5.4.3.2/1"},
		Ip6:     []string{"87:65:43::/21"},
		Include: []string{"_spf.example.com", "_spf2.example.com"},
		AllRune: '~',
	}
	_, err := r1.Split()
	if err == nil {
		t.Error("Split should not allow includes")
	}
}

func TestParse(t *testing.T) {
	txt := "v=spf1 ip4:1.2.3.4/5 ip6:12:34:56::/78 include:_spf.example.com ~all"
	spf := NewSPF()
	err := spf.Parse(txt)
	if err != nil {
		t.Errorf("Failed to parse: %s", err)
	}
	if len(spf.Ip4) != 1 || spf.Ip4[0] != "1.2.3.4/5" {
		t.Errorf("Didn't get ip4: %v", spf.Ip4)
	}
	if len(spf.Ip6) != 1 || spf.Ip6[0] != "12:34:56::/78" {
		t.Errorf("Didn't get ip6: %v", spf.Ip6)
	}
	if len(spf.Include) != 1 || spf.Include[0] != "_spf.example.com" {
		t.Errorf("Didn't get include: %v", spf.Include)
	}
	if spf.AllRune != '~' {
		t.Errorf("Didn't get allRune: %v", spf.AllRune)
	}
}

type TestQuerent struct {
	responses [][]string
	iter      int
}

func (q *TestQuerent) Query(name string) ([]string, error) {
	q.iter %= len(q.responses)
	res := q.responses[q.iter]
	q.iter++
	return res, nil
}

func TestFlatten(t *testing.T) {
	querent := TestQuerent{
		responses: [][]string{[]string{
			"v=spf1 ip4:1.2.3.4/5 ~all",
		}, []string{
			"v=spf1 ip6:12:34:56::/78 ?all",
		}},
	}
	r1 := &SPF{
		V:       "spf1",
		Ip4:     []string{"5.4.3.2/1"},
		Ip6:     []string{"87:65:43::/21"},
		Include: []string{"_spf.example.com", "_spf2.example.com"},
		AllRune: '-',
		Querent: &querent,
	}
	flat, err := r1.Flatten()

	if err != nil {
		t.Errorf("Error during flatten: %s", err)
	}

	ip4exp := []string{"1.2.3.4/5", "5.4.3.2/1"}
	for _, ip4 := range ip4exp {
		if !strInSlice(ip4, flat.Ip4) {
			t.Errorf("Failed to find string %s in flat.ip4", ip4)
		}
	}
	ip6exp := []string{"12:34:56::/78", "87:65:43::/21"}
	for _, ip6 := range ip6exp {
		if !strInSlice(ip6, flat.Ip6) {
			t.Errorf("Failed to find string %s in flat.ip6", ip6)
		}
	}
	if len(flat.Include) > 0 {
		t.Errorf("Should not have any includes after flattening: %s", flat.Include)
	}
	if flat.AllRune != '-' {
		t.Errorf("Failed to set allRune: %c", flat.AllRune)
	}
}
