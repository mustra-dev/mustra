package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Agents and servers upgrade independently, so a Self Service state reply
// crosses versions in both directions.

// An older server sends neither categories nor category_ids: a current
// agent decodes the reply as it always did, with nothing filed anywhere.
func TestSelfServiceReplyFromOlderServer(t *testing.T) {
	old := `{"ok":true,"hostname":"FIN-LT-0142","items":[
		{"id":"p1","name":"Google Chrome","description":"Web browser.","category":"Browsers","icon":"","entitled":true,"pending":false,"can_request":false,"installed":false}]}`
	var r SelfServiceReply
	if err := json.Unmarshal([]byte(old), &r); err != nil {
		t.Fatal(err)
	}
	if !r.OK || len(r.Items) != 1 || r.Items[0].Category != "Browsers" {
		t.Fatalf("decoded %+v", r)
	}
	if r.Categories != nil || r.Items[0].CategoryIDs != nil {
		t.Fatalf("categories appeared from nowhere: %+v %+v", r.Categories, r.Items[0].CategoryIDs)
	}
}

// An older agent knows only the single category string. A current
// server's reply still carries it, and the new fields are ones an older
// agent's struct simply does not have.
func TestSelfServiceReplyToOlderAgent(t *testing.T) {
	cur := SelfServiceReply{OK: true,
		Categories: []SelfServiceCategory{{ID: "sscat-browsers", Name: "Browsers", Icon: "globe"}},
		Items: []SelfServiceItem{{ID: "p1", Name: "Google Chrome", Category: "Browsers",
			CategoryIDs: []string{"sscat-browsers"}, Entitled: true}}}
	raw, err := json.Marshal(cur)
	if err != nil {
		t.Fatal(err)
	}
	// The item and reply as an agent from before categories declared them.
	var old struct {
		OK    bool `json:"ok"`
		Items []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
			Entitled bool   `json:"entitled"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if !old.OK || len(old.Items) != 1 || old.Items[0].Category != "Browsers" || !old.Items[0].Entitled {
		t.Fatalf("an older agent read %+v from %s", old, raw)
	}
}

// Nothing filed: the reply carries no category keys at all, so the window
// falls back to the per-item string exactly as with an older server.
func TestSelfServiceReplyOmitsEmptyCategories(t *testing.T) {
	raw, err := json.Marshal(SelfServiceReply{OK: true, Items: []SelfServiceItem{{ID: "p1", Name: "7-Zip"}}})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(raw); strings.Contains(s, "categories") || strings.Contains(s, "category_ids") {
		t.Fatalf("empty categories were sent: %s", s)
	}
}
