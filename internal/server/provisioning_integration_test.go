package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/server/vault"
	"github.com/mustra-dev/mustra/internal/store"
)

func provisioningTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	v, err := vault.New(st, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{logger: slog.Default(), store: st, vault: v, live: &liveConfig{}, syslog: &syslogSink{}}
	s.auth = auth.New(ctx, st, nil, false, slog.Default())
	if err := st.SetSetting(ctx, settingAgentPublicURL, "https://console.example.com", "test"); err != nil {
		t.Fatal(err)
	}
	return s, st
}

func setProvisioning(t *testing.T, st *store.Store, c provisioningConfig) {
	t.Helper()
	c.applyDefaults()
	raw, _ := json.Marshal(c)
	if err := st.SetSetting(context.Background(), settingProvisioning, string(raw), "test"); err != nil {
		t.Fatal(err)
	}
}

// The whole boot path over HTTP: off by default, unknown and unarmed
// MACs boot their disk, an armed one gets its installer with a token, the
// answer file is served once with a fresh enrollment token and disarms
// the machine, and the installer's status report is taken.
func TestProvisioningBootFlow(t *testing.T) {
	s, st := provisioningTestServer(t)
	ctx := context.Background()
	t.Cleanup(func() { setProvisioning(t, st, provisioningConfig{}) })
	srv := httptest.NewServer(s.bootRoutes())
	defer srv.Close()
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	run := idgen.New("")[:6]
	mac := "02:00:00:" + run[0:2] + ":" + run[2:4] + ":" + run[4:6]
	setProvisioning(t, st, provisioningConfig{})
	if code, _ := get("/boot/ipxe?mac=" + mac); code != http.StatusNotFound {
		t.Fatalf("provisioning off: %d, want 404", code)
	}
	setProvisioning(t, st, provisioningConfig{Enabled: true, BootURL: "http://10.0.0.5:8069"})

	// Unknown MAC: the local-boot script, never an installer.
	if code, body := get("/boot/ipxe?mac=02:ff:ff:ff:ff:fe"); code != 200 || body != ipxeLocalBoot {
		t.Fatalf("unknown MAC: %d %q", code, body)
	}
	if code, body := get("/boot/ipxe?mac=${net0/mac}"); code != 200 || body != ipxeLocalBoot {
		t.Fatalf("garbage MAC: %d %q", code, body)
	}

	im, err := st.SaveProvisioningImage(ctx, store.ProvisioningImage{ID: idgen.New("pim-"), Name: "Ubuntu test " + run, Family: "ubuntu",
		Assets:        map[string]store.ProvisioningAsset{"kernel": {URL: "http://mirror.example/casper/vmlinuz"}, "initrd": {URL: "http://mirror.example/casper/initrd"}},
		InstallSource: "http://mirror.example/ubuntu.iso"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteProvisioningImage(context.Background(), im.ID) })
	m, err := st.SaveProvisioningMachine(ctx, store.ProvisioningMachine{ID: idgen.New("pmc-"), MAC: mac, Name: "lab-" + run, ImageID: im.ID,
		Variables: map[string]string{"ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqmXc7bS1nJ7aN7rL0Q5r3S4V6y7z8x9w0v1u2t3s4r ops@example"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteProvisioningMachine(context.Background(), m.ID) })
	sealed, err := s.sealProvisioningSecret("correct horse battery", "machine-admin", m.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.AdminSecret = sealed
	if m, err = st.SaveProvisioningMachine(ctx, *m); err != nil {
		t.Fatal(err)
	}

	// Known but not armed: its disk.
	if code, body := get("/boot/ipxe?mac=" + strings.ToUpper(strings.ReplaceAll(mac, ":", "-"))); code != 200 || body != ipxeLocalBoot {
		t.Fatalf("unarmed machine: %d %q", code, body)
	}
	if _, err := st.SetProvisioningArmed(ctx, m.ID, true, "tester", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	code, script := get("/boot/ipxe?mac=" + mac)
	if code != 200 || !strings.Contains(script, "kernel http://mirror.example/casper/vmlinuz") {
		t.Fatalf("armed machine: %d\n%s", code, script)
	}
	tok := regexp.MustCompile(`/boot/answer/(mpa_[A-Za-z0-9_-]{43})/`).FindStringSubmatch(script)
	if tok == nil {
		t.Fatalf("no answer token in the script:\n%s", script)
	}
	answer := "/boot/answer/" + tok[1]

	if code, body := get(answer + "/meta-data"); code != 200 || !strings.Contains(body, "local-hostname: lab-"+run) {
		t.Fatalf("meta-data: %d %q", code, body)
	}
	if code, _ := get("/boot/answer/mpa_" + strings.Repeat("A", 43) + "/user-data"); code != 404 {
		t.Fatalf("a made-up token: %d", code)
	}
	code, userData := get(answer + "/user-data")
	if code != 200 {
		t.Fatalf("user-data: %d %s", code, userData)
	}
	for _, want := range []string{"#cloud-config", `hostname: "lab-` + run + `"`, `password: "$6$`, "Authorization: Bearer mte_", "https://console.example.com/install.sh",
		"http://10.0.0.5:8069/boot/status/mps_"} {
		if !strings.Contains(userData, want) {
			t.Errorf("user-data lacks %q", want)
		}
	}
	if strings.Contains(userData, "correct horse battery") {
		t.Error("the Linux answer file carries the password in clear")
	}
	if code, _ := get(answer + "/user-data"); code != 404 {
		t.Fatalf("the answer file was served twice: %d", code)
	}
	if code, _ := get(answer + "/meta-data"); code != 404 {
		t.Fatalf("a used token still serves meta-data: %d", code)
	}
	got, _ := st.GetProvisioningMachine(ctx, m.ID)
	if got.InstallNextBoot {
		t.Fatal("the machine is still armed after its answer file was fetched")
	}
	if code, body := get("/boot/ipxe?mac=" + mac); code != 200 || body != ipxeLocalBoot {
		t.Fatalf("after the install started the machine must boot its disk: %q", body)
	}

	// The installer reports with the status token from its answer file.
	stTok := regexp.MustCompile(`/boot/status/(mps_[A-Za-z0-9_-]{43})`).FindStringSubmatch(userData)
	if stTok == nil || stTok[1] != statusTokenFor(tok[1]) {
		t.Fatalf("status token missing or not derived from the answer token")
	}
	post := func(token, status string) int {
		resp, err := http.PostForm(srv.URL+"/boot/status/"+token, url.Values{"status": {status}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(stTok[1], "rebooting"); c != 400 {
		t.Fatalf("an unknown status: %d", c)
	}
	if c := post(stTok[1], "installed"); c != 204 {
		t.Fatalf("installed: %d", c)
	}
	if c := post(stTok[1], "failed"); c != 404 {
		t.Fatalf("a finished install took another report: %d", c)
	}
	installs, err := st.ListProvisioningInstalls(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var in *store.ProvisioningInstall
	for i := range installs {
		if installs[i].MachineID == m.ID {
			in = &installs[i]
			break
		}
	}
	if in == nil || in.Status != "installed" || in.EnrollTokenID == "" || in.AnswerFetchedAt == nil {
		t.Fatalf("install record: %+v", in)
	}

	// Outside the allowed networks nothing answers.
	setProvisioning(t, st, provisioningConfig{Enabled: true, BootURL: "http://10.0.0.5:8069", AllowedNetworks: []string{"192.0.2.0/24"}})
	if code, _ := get("/boot/ipxe?mac=" + mac); code != http.StatusForbidden {
		t.Fatalf("outside the allowed networks: %d", code)
	}
}

// A reimage always waits for a second person, even with no approval
// policy; an API token cannot ask for one; a MAC an endpoint reports
// cannot be armed around it; and the approved replay arms exactly that
// endpoint's machine.
func TestReimageIsApprovalGated(t *testing.T) {
	s, st := provisioningTestServer(t)
	ctx := context.Background()
	s.routes() // registers the gate the approval replays through
	setProvisioning(t, st, provisioningConfig{Enabled: true, BootURL: "http://10.0.0.5:8069"})
	t.Cleanup(func() { setProvisioning(t, st, provisioningConfig{}) })

	run := idgen.New("")[:6]
	agentID := "agt-reimage-" + run
	host := "web-" + run
	mac := "02:10:00:" + run[0:2] + ":" + run[2:4] + ":" + run[4:6]
	if err := st.UpsertOnRegister(ctx, agentID, proto.AgentInfo{Hostname: host, OS: "linux", Arch: "amd64", Version: "test"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agentID) })
	nics, _ := json.Marshal([]proto.NetworkInterfaceInfo{{Name: "eth0", MAC: strings.ToUpper(mac), Up: true}, {Name: "lo", MAC: ""}})
	if err := st.UpsertSensorData(ctx, agentID, "network", time.Now(), nics); err != nil {
		t.Fatal(err)
	}
	im, err := st.SaveProvisioningImage(ctx, store.ProvisioningImage{ID: idgen.New("pim-"), Name: "Debian test " + run, Family: "debian",
		Assets:   map[string]store.ProvisioningAsset{"kernel": {URL: "http://d.example/linux"}, "initrd": {URL: "http://d.example/initrd.gz"}},
		Defaults: map[string]string{"ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqmXc7bS1nJ7aN7rL0Q5r3S4V6y7z8x9w0v1u2t3s4r ops@example"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteProvisioningImage(context.Background(), im.ID) })

	newUser := func(perms ...string) *store.User {
		u, err := st.CreateLocalUser(ctx, idgen.New("usr-"), idgen.New("reimage-"), "", "reimage test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteUser(context.Background(), u.ID) })
		role, err := st.CreateRole(ctx, idgen.New("role-"), idgen.New("reimage-role-"), "", perms, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.DeleteRole(context.Background(), role.ID) })
		if err := st.AssignUserRole(ctx, u.ID, role.ID); err != nil {
			t.Fatal(err)
		}
		return u
	}
	operator := newUser(auth.PermDeployManage)
	reimage := func(ctx context.Context, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/reimage", strings.NewReader(body)).WithContext(ctx)
		r.SetPathValue("id", agentID)
		w := httptest.NewRecorder()
		s.handleReimage(w, r)
		return w
	}
	body := `{"image_id":"` + im.ID + `","mac":"` + mac + `","confirm_hostname":"` + strings.ToUpper(host) + `"}`
	userCtx := auth.WithUser(ctx, operator)

	if w := reimage(userCtx, strings.Replace(body, strings.ToUpper(host), "someone-else", 1)); w.Code != http.StatusBadRequest {
		t.Fatalf("a wrong hostname confirmation: %d %s", w.Code, w.Body)
	}
	if w := reimage(userCtx, strings.Replace(body, mac, "02:99:99:99:99:99", 1)); w.Code != http.StatusBadRequest {
		t.Fatalf("a MAC the endpoint does not report: %d %s", w.Code, w.Body)
	}
	tokCtx := auth.WithToken(auth.WithUser(ctx, &store.User{ID: auth.APITokenUserID, Username: "token:ci"}), []string{auth.PermDeployManage},
		&auth.TokenInfo{ID: "tok-1", ApprovalExempt: true})
	if w := reimage(tokCtx, body); w.Code != http.StatusForbidden {
		t.Fatalf("an approval-exempt API token: %d %s, want 403", w.Code, w.Body)
	}

	w := reimage(userCtx, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("a reimage with no policy configured: %d %s, want 202 (parked)", w.Code, w.Body)
	}
	var parked struct {
		RequestID string `json:"request_id"`
		Policy    string `json:"policy"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &parked)
	if parked.Policy != builtinReimagePolicy.Name {
		t.Fatalf("parked under %q", parked.Policy)
	}
	if mm, _ := st.GetProvisioningMachineByMAC(ctx, mac); mm != nil {
		t.Fatal("the machine was armed before anybody approved")
	}
	req, err := st.GetApprovalRequest(ctx, parked.RequestID)
	if err != nil || req == nil {
		t.Fatalf("approval request: %v", err)
	}
	if len(req.AgentIDs) != 1 || req.AgentIDs[0] != agentID || req.Module != "provisioning" {
		t.Fatalf("the approval names %v in %q, want exactly %s", req.AgentIDs, req.Module, agentID)
	}

	// Approved: the replay runs as the requester, arms the machine for
	// that endpoint, and (no bus here) falls back to manual instructions.
	s.runApproved(ctx, *req)
	done, _ := st.GetApprovalRequest(ctx, req.ID)
	if done.State != "approved" || !strings.Contains(done.Outcome, `"method":"manual"`) {
		t.Fatalf("replay: %s %s", done.State, done.Outcome)
	}
	mm, err := st.GetProvisioningMachineByMAC(ctx, mac)
	if err != nil || mm == nil || !mm.Armed(time.Now()) || mm.AgentID != agentID || mm.Variables["hostname"] != host {
		t.Fatalf("machine after the approved reimage: %+v", mm)
	}
	t.Cleanup(func() { _, _ = st.DeleteProvisioningMachine(context.Background(), mm.ID) })

	// The machines API will not arm an endpoint's MAC around the reimage.
	if _, err := st.SetProvisioningArmed(ctx, mm.ID, false, "t", time.Time{}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/provisioning/machines/"+mm.ID+"/arm", strings.NewReader(`{"install_next_boot":true}`)).WithContext(userCtx)
	r.SetPathValue("id", mm.ID)
	aw := httptest.NewRecorder()
	s.handleArmProvisioningMachine(aw, r)
	if aw.Code != http.StatusConflict {
		t.Fatalf("arming an endpoint's MAC directly: %d %s, want 409", aw.Code, aw.Body)
	}
}
