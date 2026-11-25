package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// OS provisioning (#95): installer images, the machines that may boot
// them, and each install that happened. See the provisioning section of
// schema.sql.

// ProvisioningAsset is one boot file of an image: fetched by the booting
// machine from URL, or served by mustra from an uploaded file.
type ProvisioningAsset struct {
	URL       string `json:"url,omitempty"`
	FileID    string `json:"file_id,omitempty"`
	Name      string `json:"name,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// ProvisioningImage is one installer in the catalog. The sealed secrets
// never leave the server; HasSourceSecret and HasAdminSecret say whether
// one is set.
type ProvisioningImage struct {
	ID              string                       `json:"id" api:"readonly"`
	Name            string                       `json:"name" api:"required"`
	Family          string                       `json:"family" api:"required"` // ubuntu | debian | windows
	Assets          map[string]ProvisioningAsset `json:"assets"`
	InstallSource   string                       `json:"install_source"`
	SourceUser      string                       `json:"source_user"`
	SourceSecret    []byte                       `json:"-"`
	HasSourceSecret bool                         `json:"has_source_secret" api:"readonly"`
	KernelArgs      string                       `json:"kernel_args"`
	Defaults        map[string]string            `json:"defaults"`
	AdminSecret     []byte                       `json:"-"`
	HasAdminSecret  bool                         `json:"has_admin_password" api:"readonly"`
	AnswerTemplate  string                       `json:"answer_template"`
	CreatedBy       string                       `json:"created_by" api:"readonly"`
	CreatedAt       time.Time                    `json:"created_at" api:"readonly"`
	UpdatedAt       time.Time                    `json:"updated_at" api:"readonly"`
}

const provisioningImageColumns = `id, name, family, assets, install_source, source_user, source_secret,
	kernel_args, defaults, admin_secret, answer_template, created_by, created_at, updated_at`

func scanProvisioningImage(row pgx.Row) (*ProvisioningImage, error) {
	var im ProvisioningImage
	var assets, defaults []byte
	if err := row.Scan(&im.ID, &im.Name, &im.Family, &assets, &im.InstallSource, &im.SourceUser, &im.SourceSecret,
		&im.KernelArgs, &defaults, &im.AdminSecret, &im.AnswerTemplate, &im.CreatedBy, &im.CreatedAt, &im.UpdatedAt); err != nil {
		return nil, err
	}
	im.Assets = map[string]ProvisioningAsset{}
	im.Defaults = map[string]string{}
	if len(assets) > 0 {
		if err := json.Unmarshal(assets, &im.Assets); err != nil {
			return nil, fmt.Errorf("image %s assets: %w", im.ID, err)
		}
	}
	if len(defaults) > 0 {
		if err := json.Unmarshal(defaults, &im.Defaults); err != nil {
			return nil, fmt.Errorf("image %s defaults: %w", im.ID, err)
		}
	}
	im.HasSourceSecret = len(im.SourceSecret) > 0
	im.HasAdminSecret = len(im.AdminSecret) > 0
	return &im, nil
}

func (s *Store) ListProvisioningImages(ctx context.Context) ([]ProvisioningImage, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+provisioningImageColumns+` FROM provisioning_images ORDER BY name, id`)
	if err != nil {
		return nil, fmt.Errorf("list provisioning images: %w", err)
	}
	defer rows.Close()
	out := []ProvisioningImage{}
	for rows.Next() {
		im, err := scanProvisioningImage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan provisioning image: %w", err)
		}
		out = append(out, *im)
	}
	return out, rows.Err()
}

// GetProvisioningImage returns one image, or nil when there is none.
func (s *Store) GetProvisioningImage(ctx context.Context, id string) (*ProvisioningImage, error) {
	im, err := scanProvisioningImage(s.pool.QueryRow(ctx, `SELECT `+provisioningImageColumns+` FROM provisioning_images WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get provisioning image: %w", err)
	}
	return im, nil
}

// SaveProvisioningImage inserts or replaces an image. The sealed secrets
// are written as given: the caller carries an unchanged one over.
func (s *Store) SaveProvisioningImage(ctx context.Context, im ProvisioningImage) (*ProvisioningImage, error) {
	assets, err := json.Marshal(nonNilAssets(im.Assets))
	if err != nil {
		return nil, err
	}
	defaults, err := json.Marshal(nonNilStringMap(im.Defaults))
	if err != nil {
		return nil, err
	}
	const q = `
INSERT INTO provisioning_images (id, name, family, assets, install_source, source_user, source_secret,
	kernel_args, defaults, admin_secret, answer_template, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
ON CONFLICT (id) DO UPDATE SET
	name = EXCLUDED.name, family = EXCLUDED.family, assets = EXCLUDED.assets,
	install_source = EXCLUDED.install_source, source_user = EXCLUDED.source_user,
	source_secret = EXCLUDED.source_secret, kernel_args = EXCLUDED.kernel_args,
	defaults = EXCLUDED.defaults, admin_secret = EXCLUDED.admin_secret,
	answer_template = EXCLUDED.answer_template, updated_at = now()
RETURNING ` + provisioningImageColumns
	out, err := scanProvisioningImage(s.pool.QueryRow(ctx, q, im.ID, im.Name, im.Family, assets, im.InstallSource,
		im.SourceUser, im.SourceSecret, im.KernelArgs, defaults, im.AdminSecret, im.AnswerTemplate, im.CreatedBy))
	if err != nil {
		return nil, fmt.Errorf("save provisioning image: %w", err)
	}
	return out, nil
}

// DeleteProvisioningImage removes an image and returns it, or nil when
// there was none. Machines assigned to it keep the id and boot their own
// disk until they are given another.
func (s *Store) DeleteProvisioningImage(ctx context.Context, id string) (*ProvisioningImage, error) {
	im, err := scanProvisioningImage(s.pool.QueryRow(ctx, `DELETE FROM provisioning_images WHERE id = $1 RETURNING `+provisioningImageColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delete provisioning image: %w", err)
	}
	return im, nil
}

func nonNilAssets(m map[string]ProvisioningAsset) map[string]ProvisioningAsset {
	if m == nil {
		return map[string]ProvisioningAsset{}
	}
	return m
}

func nonNilStringMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// ProvisioningMachine is one MAC address the boot server knows.
type ProvisioningMachine struct {
	ID              string            `json:"id" api:"readonly"`
	MAC             string            `json:"mac" api:"required"`
	Name            string            `json:"name"`
	ImageID         string            `json:"image_id"`
	Variables       map[string]string `json:"variables"`
	AdminSecret     []byte            `json:"-"`
	HasAdminSecret  bool              `json:"has_admin_password" api:"readonly"`
	AgentID         string            `json:"agent_id" api:"readonly"`
	InstallNextBoot bool              `json:"install_next_boot" api:"readonly"`
	ArmedBy         string            `json:"armed_by" api:"readonly"`
	ArmedAt         *time.Time        `json:"armed_at,omitempty" api:"readonly"`
	ArmExpiresAt    *time.Time        `json:"arm_expires_at,omitempty" api:"readonly"`
	LastBootAt      *time.Time        `json:"last_boot_at,omitempty" api:"readonly"`
	LastBootIP      string            `json:"last_boot_ip" api:"readonly"`
	CreatedBy       string            `json:"created_by" api:"readonly"`
	CreatedAt       time.Time         `json:"created_at" api:"readonly"`
	UpdatedAt       time.Time         `json:"updated_at" api:"readonly"`
}

// Armed reports whether the machine installs at its next network boot.
func (m ProvisioningMachine) Armed(now time.Time) bool {
	return m.InstallNextBoot && m.ArmExpiresAt != nil && now.Before(*m.ArmExpiresAt)
}

const provisioningMachineColumns = `id, mac, name, image_id, variables, admin_secret, agent_id, install_next_boot,
	armed_by, armed_at, arm_expires_at, last_boot_at, last_boot_ip, created_by, created_at, updated_at`

func scanProvisioningMachine(row pgx.Row) (*ProvisioningMachine, error) {
	var m ProvisioningMachine
	var vars []byte
	if err := row.Scan(&m.ID, &m.MAC, &m.Name, &m.ImageID, &vars, &m.AdminSecret, &m.AgentID, &m.InstallNextBoot,
		&m.ArmedBy, &m.ArmedAt, &m.ArmExpiresAt, &m.LastBootAt, &m.LastBootIP, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
		return nil, err
	}
	m.Variables = map[string]string{}
	if len(vars) > 0 {
		if err := json.Unmarshal(vars, &m.Variables); err != nil {
			return nil, fmt.Errorf("machine %s variables: %w", m.ID, err)
		}
	}
	m.HasAdminSecret = len(m.AdminSecret) > 0
	return &m, nil
}

func (s *Store) ListProvisioningMachines(ctx context.Context) ([]ProvisioningMachine, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+provisioningMachineColumns+` FROM provisioning_machines ORDER BY name, mac`)
	if err != nil {
		return nil, fmt.Errorf("list provisioning machines: %w", err)
	}
	defer rows.Close()
	out := []ProvisioningMachine{}
	for rows.Next() {
		m, err := scanProvisioningMachine(rows)
		if err != nil {
			return nil, fmt.Errorf("scan provisioning machine: %w", err)
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// GetProvisioningMachine returns one machine by id, or nil.
func (s *Store) GetProvisioningMachine(ctx context.Context, id string) (*ProvisioningMachine, error) {
	return s.getProvisioningMachine(ctx, `id = $1`, id)
}

// GetProvisioningMachineByMAC returns the machine with this (normalized)
// MAC, or nil.
func (s *Store) GetProvisioningMachineByMAC(ctx context.Context, mac string) (*ProvisioningMachine, error) {
	return s.getProvisioningMachine(ctx, `mac = $1`, mac)
}

func (s *Store) getProvisioningMachine(ctx context.Context, where string, arg any) (*ProvisioningMachine, error) {
	m, err := scanProvisioningMachine(s.pool.QueryRow(ctx, `SELECT `+provisioningMachineColumns+` FROM provisioning_machines WHERE `+where, arg))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get provisioning machine: %w", err)
	}
	return m, nil
}

// ErrMACTaken is returned when another machine record has the MAC.
var ErrMACTaken = errors.New("another machine already has that MAC address")

// SaveProvisioningMachine inserts or updates a machine's identity, image
// and variables. The arming columns are left alone: SetProvisioningArmed
// is the only thing that changes them.
func (s *Store) SaveProvisioningMachine(ctx context.Context, m ProvisioningMachine) (*ProvisioningMachine, error) {
	vars, err := json.Marshal(nonNilStringMap(m.Variables))
	if err != nil {
		return nil, err
	}
	const q = `
INSERT INTO provisioning_machines (id, mac, name, image_id, variables, admin_secret, agent_id, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (id) DO UPDATE SET
	mac = EXCLUDED.mac, name = EXCLUDED.name, image_id = EXCLUDED.image_id,
	variables = EXCLUDED.variables, admin_secret = EXCLUDED.admin_secret,
	agent_id = EXCLUDED.agent_id, updated_at = now()
RETURNING ` + provisioningMachineColumns
	out, err := scanProvisioningMachine(s.pool.QueryRow(ctx, q, m.ID, m.MAC, m.Name, m.ImageID, vars, m.AdminSecret, m.AgentID, m.CreatedBy))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrMACTaken
		}
		return nil, fmt.Errorf("save provisioning machine: %w", err)
	}
	return out, nil
}

// SetProvisioningArmed sets or clears a machine's "install next boot"
// flag. Arming records who and until when; disarming clears both.
func (s *Store) SetProvisioningArmed(ctx context.Context, id string, armed bool, by string, until time.Time) (*ProvisioningMachine, error) {
	var q string
	args := []any{id}
	if armed {
		q = `UPDATE provisioning_machines SET install_next_boot = true, armed_by = $2, armed_at = now(), arm_expires_at = $3, updated_at = now()
WHERE id = $1 RETURNING ` + provisioningMachineColumns
		args = append(args, by, until)
	} else {
		q = `UPDATE provisioning_machines SET install_next_boot = false, arm_expires_at = NULL, updated_at = now()
WHERE id = $1 RETURNING ` + provisioningMachineColumns
	}
	m, err := scanProvisioningMachine(s.pool.QueryRow(ctx, q, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("arm provisioning machine: %w", err)
	}
	// Arming afresh or disarming both withdraw a boot script already
	// served: its answer token must not outlive the decision it was
	// served under.
	if err := s.CancelPendingProvisioningInstalls(ctx, id, "withdrawn: the machine was armed again or disarmed"); err != nil {
		return nil, err
	}
	return m, nil
}

// CancelPendingProvisioningInstalls supersedes every install of a machine
// that has not fetched its answer file yet, so its token stops working.
func (s *Store) CancelPendingProvisioningInstalls(ctx context.Context, machineID, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE provisioning_installs SET status = 'superseded', detail = $2, updated_at = now()
WHERE machine_id = $1 AND status = 'script_served'`, machineID, detail)
	if err != nil {
		return fmt.Errorf("cancel provisioning installs: %w", err)
	}
	return nil
}

// DeleteProvisioningMachine removes a machine and returns it, or nil.
func (s *Store) DeleteProvisioningMachine(ctx context.Context, id string) (*ProvisioningMachine, error) {
	m, err := scanProvisioningMachine(s.pool.QueryRow(ctx, `DELETE FROM provisioning_machines WHERE id = $1 RETURNING `+provisioningMachineColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("delete provisioning machine: %w", err)
	}
	return m, nil
}

// TouchProvisioningBoot records that a known machine asked for its boot
// script.
func (s *Store) TouchProvisioningBoot(ctx context.Context, id, ip string) error {
	_, err := s.pool.Exec(ctx, `UPDATE provisioning_machines SET last_boot_at = now(), last_boot_ip = $2 WHERE id = $1`, id, ip)
	return err
}

// ProvisioningInstall is one armed machine's network boot and what became
// of it. Status comes from the boot server and the installer's own
// callbacks; AgentID and EnrolledAt from the new agent's enrollment.
type ProvisioningInstall struct {
	ID              string     `json:"id"`
	MachineID       string     `json:"machine_id"`
	MAC             string     `json:"mac"`
	Hostname        string     `json:"hostname"`
	ImageID         string     `json:"image_id"`
	ImageName       string     `json:"image_name"`
	Family          string     `json:"family"`
	AnswerExpiresAt time.Time  `json:"answer_expires_at"`
	ScriptIP        string     `json:"script_ip"`
	AnswerFetchedAt *time.Time `json:"answer_fetched_at,omitempty"`
	AnswerIP        string     `json:"answer_ip"`
	EnrollTokenID   string     `json:"enroll_token_id"`
	Status          string     `json:"status"`
	Detail          string     `json:"detail"`
	ArmedBy         string     `json:"armed_by"`
	ReimageOf       string     `json:"reimage_of"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	// From the agent that enrolled with this install's token, if any.
	AgentID    string     `json:"agent_id,omitempty"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
}

const provisioningInstallColumns = `i.id, i.machine_id, i.mac, i.hostname, i.image_id, i.image_name, i.family,
	i.answer_expires_at, i.script_ip, i.answer_fetched_at, i.answer_ip, i.enroll_token_id, i.status, i.detail,
	i.armed_by, i.reimage_of, i.created_at, i.updated_at, COALESCE(c.agent_id, ''), c.created_at`

// The enrollment join: an install's token enrolls at most one agent.
const provisioningInstallFrom = ` FROM provisioning_installs i
LEFT JOIN agent_credentials c ON i.enroll_token_id <> '' AND c.token_id = i.enroll_token_id`

func scanProvisioningInstall(row pgx.Row) (*ProvisioningInstall, error) {
	var in ProvisioningInstall
	if err := row.Scan(&in.ID, &in.MachineID, &in.MAC, &in.Hostname, &in.ImageID, &in.ImageName, &in.Family,
		&in.AnswerExpiresAt, &in.ScriptIP, &in.AnswerFetchedAt, &in.AnswerIP, &in.EnrollTokenID, &in.Status, &in.Detail,
		&in.ArmedBy, &in.ReimageOf, &in.CreatedAt, &in.UpdatedAt, &in.AgentID, &in.EnrolledAt); err != nil {
		return nil, err
	}
	return &in, nil
}

// ListProvisioningInstalls returns the newest installs first.
func (s *Store) ListProvisioningInstalls(ctx context.Context, limit int) ([]ProvisioningInstall, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT `+provisioningInstallColumns+provisioningInstallFrom+` ORDER BY i.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list provisioning installs: %w", err)
	}
	defer rows.Close()
	out := []ProvisioningInstall{}
	for rows.Next() {
		in, err := scanProvisioningInstall(rows)
		if err != nil {
			return nil, fmt.Errorf("scan provisioning install: %w", err)
		}
		out = append(out, *in)
	}
	return out, rows.Err()
}

// NewProvisioningInstall is what the boot server records when it hands an
// armed machine its installer.
type NewProvisioningInstall struct {
	ID, MachineID, MAC, Hostname, ImageID, ImageName, Family string
	AnswerTokenHash, StatusTokenHash                         string
	AnswerExpiresAt, StatusExpiresAt                         time.Time
	ScriptIP, ArmedBy, ReimageOf                             string
}

// StartProvisioningInstall records a served boot script. Any earlier
// install of the machine still waiting for its answer file is superseded,
// so only the newest script's token can fetch one.
func (s *Store) StartProvisioningInstall(ctx context.Context, n NewProvisioningInstall) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE provisioning_installs SET status = 'superseded', updated_at = now(),
	detail = 'the machine asked for its boot script again before fetching this answer file'
WHERE machine_id = $1 AND status = 'script_served'`, n.MachineID); err != nil {
		return fmt.Errorf("supersede provisioning installs: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO provisioning_installs (id, machine_id, mac, hostname, image_id, image_name, family,
	answer_token_hash, status_token_hash, answer_expires_at, status_expires_at, script_ip, armed_by, reimage_of)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		n.ID, n.MachineID, n.MAC, n.Hostname, n.ImageID, n.ImageName, n.Family, n.AnswerTokenHash, n.StatusTokenHash,
		n.AnswerExpiresAt, n.StatusExpiresAt, n.ScriptIP, n.ArmedBy, n.ReimageOf); err != nil {
		return fmt.Errorf("record provisioning install: %w", err)
	}
	return tx.Commit(ctx)
}

// ProvisioningAnswerClaim is an install whose answer token is still good.
type ProvisioningAnswerClaim struct {
	InstallID, MachineID, Family, Hostname string
}

// PeekProvisioningAnswer finds the install a still-unused, unexpired
// answer token belongs to, without using it up. It serves the files an
// installer reads before its answer file (cloud-init's meta-data, WinPE's
// launcher), which carry nothing the answer file does not.
func (s *Store) PeekProvisioningAnswer(ctx context.Context, tokenHash string) (*ProvisioningAnswerClaim, error) {
	var c ProvisioningAnswerClaim
	err := s.pool.QueryRow(ctx, `SELECT id, machine_id, family, hostname FROM provisioning_installs
WHERE answer_token_hash = $1 AND status = 'script_served' AND answer_fetched_at IS NULL AND answer_expires_at > now()`, tokenHash).
		Scan(&c.InstallID, &c.MachineID, &c.Family, &c.Hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("peek provisioning answer: %w", err)
	}
	return &c, nil
}

// ClaimProvisioningAnswer uses an answer token up: in one transaction it
// marks the install's answer fetched and clears the machine's "install
// next boot" flag, so the token works once and the machine boots its own
// disk from then on. It returns nil when the token is unknown, expired,
// superseded or already used.
func (s *Store) ClaimProvisioningAnswer(ctx context.Context, tokenHash, ip string) (*ProvisioningAnswerClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var c ProvisioningAnswerClaim
	err = tx.QueryRow(ctx, `UPDATE provisioning_installs SET answer_fetched_at = now(), answer_ip = $2,
	status = 'answer_served', updated_at = now()
WHERE answer_token_hash = $1 AND status = 'script_served' AND answer_fetched_at IS NULL AND answer_expires_at > now()
RETURNING id, machine_id, family, hostname`, tokenHash, ip).Scan(&c.InstallID, &c.MachineID, &c.Family, &c.Hostname)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim provisioning answer: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE provisioning_machines SET install_next_boot = false, arm_expires_at = NULL, updated_at = now()
WHERE id = $1`, c.MachineID); err != nil {
		return nil, fmt.Errorf("disarm provisioning machine: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

// SetProvisioningInstallEnrollToken records the enrollment token minted
// for an install's answer file.
func (s *Store) SetProvisioningInstallEnrollToken(ctx context.Context, installID, tokenID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE provisioning_installs SET enroll_token_id = $2, updated_at = now() WHERE id = $1`, installID, tokenID)
	return err
}

// FailProvisioningInstall marks an install failed with a reason, whatever
// state it was in.
func (s *Store) FailProvisioningInstall(ctx context.Context, installID, detail string) error {
	_, err := s.pool.Exec(ctx, `UPDATE provisioning_installs SET status = 'failed', detail = $2, updated_at = now() WHERE id = $1`, installID, detail)
	return err
}

// ReportProvisioningStatus applies an installer's callback. The status
// token is accepted only after the answer file was served, before its
// expiry, and while the install has not finished, so a token read out of
// an answer file cannot rewrite history later. It returns the install, or
// nil when the token is not accepted.
func (s *Store) ReportProvisioningStatus(ctx context.Context, tokenHash, status, detail string) (*ProvisioningInstall, error) {
	var id string
	err := s.pool.QueryRow(ctx, `UPDATE provisioning_installs SET status = $2, detail = $3, updated_at = now()
WHERE status_token_hash = $1 AND status_expires_at > now() AND answer_fetched_at IS NOT NULL
  AND status IN ('answer_served', 'installing')
RETURNING id`, tokenHash, status, detail).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("report provisioning status: %w", err)
	}
	return scanProvisioningInstall(s.pool.QueryRow(ctx, `SELECT `+provisioningInstallColumns+provisioningInstallFrom+` WHERE i.id = $1`, id))
}
