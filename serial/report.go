package serial

import "labelreef/zone"

type DeltaStatus struct {
	From    uint32 `json:"from"`
	To      uint32 `json:"to"`
	Deletes int    `json:"deletes"`
	Adds    int    `json:"adds"`
}

type Inventory struct {
	Format      int           `json:"format"`
	Origin      string        `json:"origin"`
	Generation  uint64        `json:"generation"`
	Serial      uint32        `json:"serial"`
	Records     int           `json:"records"`
	Nodes       int           `json:"nodes"`
	Fingerprint string        `json:"fingerprint"`
	History     []DeltaStatus `json:"history"`
	SOA         zone.RecordV1 `json:"soa"`
}

func (s *Snapshot) Inventory() Inventory {
	z := s.Current()
	view := Inventory{
		Format: 1, Origin: z.Origin(), Generation: s.Generation(), Serial: z.Serial(),
		Records: z.RecordCount(), Nodes: z.NodeCount(), Fingerprint: z.Fingerprint(),
		History: make([]DeltaStatus, 0, len(s.deltas)), SOA: zone.RecordToV1(z.SOA()),
	}
	for _, d := range s.deltas {
		view.History = append(view.History, DeltaStatus{
			From: d.From(), To: d.To(), Deletes: len(d.Deletes), Adds: len(d.Adds),
		})
	}
	return view
}
