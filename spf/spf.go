package spf

import (
	"errors"
	"math"
	"strings"
)

// http://www.openspf.org/RFC_4408#rsize
// A TXT response should never exceed 512 bytes. This includes the domain name
// and any other TXT records returned in the same response.
// A standard record looks like:
// v=spf1 ip4:123.123.123.123/12 ip6:1234:1234:1234::12 -all
// [--7--][---------23----------][---------23----------][-4]
// Therefore, to guarantee we don't exceed 450 octets:
// 450 >= 7 + 23*ips + 4
//  19 >= ips
const MAX_CIDRS = 19

// A, Mx, Ptr mechanisms not supported
type SPF struct {
	V           string
	Ip4         []string
	Ip6         []string
	Include     []string
	AllRune     byte
	Querent     TXTQuerent
	LookupCount int
}

func NewSPF() *SPF {
	return &SPF{
		V:           "spf1",
		Ip4:         []string{},
		Ip6:         []string{},
		Include:     []string{},
		AllRune:     '?', // least restrictive
		Querent:     SimpleTXTQuerent{},
		LookupCount: 0,
	}
}

func (spf *SPF) Clone() *SPF {
	rec := NewSPF()
	return rec.Append(spf)
}

func strInSlice(s string, a []string) bool {
	for _, e := range a {
		if e == s {
			return true
		}
	}
	return false
}

func (s *SPF) Append(spfs ...*SPF) *SPF {
	for _, spf := range spfs {
		for _, ip4 := range spf.Ip4 {
			// dedup while appending
			if !strInSlice(ip4, s.Ip4) {
				s.Ip4 = append(s.Ip4, ip4)
			}
		}
		for _, ip6 := range spf.Ip6 {
			// dedup while appending
			if !strInSlice(ip6, s.Ip6) {
				s.Ip6 = append(s.Ip6, ip6)
			}
		}
		s.Include = append(s.Include, spf.Include...)
		if s.AllRune != spf.AllRune {
			if s.AllRune == '-' || spf.AllRune == '-' {
				// most restrictive
				s.AllRune = '-'
			} else {
				s.AllRune = '~'
			}
		}
	}
	return s
}

// If the IP CIDRs won't fit into one record, the client (of this package)
// has to deal with splitting them across different requests. But we can
// help by returning multiple SPF records that do fit.
func (s *SPF) Split() ([]*SPF, error) {
	if len(s.Include) > 0 {
		return nil, errors.New("Record cannot have includes when splitting")
	}
	// Don't want to modify the original input
	spf := s.Clone()

	numRecords := int(math.Ceil(float64(len(spf.Ip4)+len(spf.Ip6)) / MAX_CIDRS))
	if numRecords == 1 {
		// Record is small enough, just return it!
		return []*SPF{spf}, nil
	}

	records := []*SPF{}
	for i := 0; i < numRecords; i++ {
		space := MAX_CIDRS
		rec := NewSPF()

		fours := int(math.Min(float64(space), float64(len(spf.Ip4))))
		rec.Ip4 = spf.Ip4[0:fours]
		space -= fours
		spf.Ip4 = spf.Ip4[fours:]

		sixes := int(math.Min(float64(space), float64(len(spf.Ip6))))
		rec.Ip6 = spf.Ip6[0:sixes]
		space -= sixes
		spf.Ip6 = spf.Ip6[sixes:]

		rec.AllRune = spf.AllRune

		records = append(records, rec)
	}
	return records, nil
}

// Returns error if this is not an SPF record
func (spf *SPF) Parse(txt string) error {
	if !strings.HasPrefix(txt, "v=spf1") {
		return errors.New("Not a valid SPF record: " + txt)
	}
	// throw away any data in the struct already
	spf.Ip4 = []string{}
	spf.Ip6 = []string{}
	spf.Include = []string{}
	// parse
	for _, part := range strings.Fields(txt) {
		switch {
		case strings.HasPrefix(part, "v="):
			spf.V = part[2:]
		case strings.HasPrefix(part, "ip4:"):
			spf.Ip4 = append(spf.Ip4, part[4:])
		case strings.HasPrefix(part, "ip6:"):
			spf.Ip6 = append(spf.Ip6, part[4:])
		case strings.HasPrefix(part, "include:"):
			spf.Include = append(spf.Include, part[8:])
		case strings.HasSuffix(part, "all"):
			spf.AllRune = part[0]
		default:
			panic("Unrecognized SPF mechanism " + part)
		}
	}
	return nil
}

// Recursively resolve any includes down to ip4 and ip6 mechanisms only
func (spf *SPF) Flatten() (*SPF, error) {
	aggregate := NewSPF()
	// First copy over any ip4/ip6 entries and all setting
	if len(spf.Ip4) > 0 {
		aggregate.Ip4 = make([]string, len(spf.Ip4))
		copy(aggregate.Ip4, spf.Ip4)
	}
	if len(spf.Ip6) > 0 {
		aggregate.Ip6 = make([]string, len(spf.Ip6))
		copy(aggregate.Ip6, spf.Ip6)
	}
	aggregate.AllRune = spf.AllRune

	// Then flatten by recursively resolving any includes
	for _, include := range spf.Include {
		// This may produce multiple TXT records, not all of which will be SPF
		txts, err := spf.Querent.Query(include)
		aggregate.LookupCount++
		if err != nil {
			// Net error means bad response, fail because this should not happen
			return nil, err
		}

		for _, txt := range txts {
			rec := NewSPF()
			// Ignore errors
			rec.Parse(txt)
			if len(rec.Include) > 0 {
				rec, err = rec.Flatten()
				if err != nil {
					return nil, err
				}
			}
			aggregate.Append(rec)
			aggregate.LookupCount += rec.LookupCount
		}
	}
	return aggregate, nil
}

// Produces a single TXT SPF record, only including ip4 and ip6, even if it is too long
func (spf *SPF) AsTXTRecord() string {
	parts := []string{"v=spf1"}
	for _, ip4 := range spf.Ip4 {
		parts = append(parts, "ip4:"+ip4)
	}
	for _, ip6 := range spf.Ip6 {
		parts = append(parts, "ip6:"+ip6)
	}
	for _, include := range spf.Include {
		parts = append(parts, "include:"+include)
	}
	parts = append(parts, string(spf.AllRune)+"all")
	return strings.Join(parts, " ")
}
