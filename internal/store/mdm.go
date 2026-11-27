package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustra-dev/mustra/internal/mdm"
)

// Apple MDM: the server's configuration, enrollment tokens, issued device
// identities, enrolled devices, their command queues and the profile
// library. The protocol itself is internal/mdm.

// MDMConfig is the single row of mdm_config. Sealed fields hold vault
// ciphertext ("vault:<base64>") and are never sent to the console.
type MDMConfig struct {
	Enabled          bool
	Organization     string
	PushCertPEM      string
	PushKeySealed    string
	PushTopic        string
	PushExpiresAt    *time.Time
	PushCSRPEM       string
	PushCSRKeySealed string
	CACertPEM        string
	CAKeySealed      string
	SignCertPEM      string
	SignKeySealed    string
	UpdatedBy        string
	UpdatedAt        time.Time
}

const mdmConfigColumns = `enabled, organization, push_cert_pem, push_key_sealed, push_topic, push_expires_at, push_csr_pem,
	push_csr_key_sealed, ca_cert_pem, ca_key_sealed, sign_cert_pem, sign_key_sealed, updated_by, updated_at`

// GetMDMConfig returns the configuration, or a zero one (off) when none
// was ever saved.
func (s *Store) GetMDMConfig(ctx context.Context) (*MDMConfig, error) {
	var c MDMConfig
	err := s.pool.QueryRow(ctx, `SELECT `+mdmConfigColumns+` FROM mdm_config WHERE id = 1`).Scan(
		&c.Enabled, &c.Organization, &c.PushCertPEM, &c.PushKeySealed, &c.PushTopic, &c.PushExpiresAt, &c.PushCSRPEM,
		&c.PushCSRKeySealed, &c.CACertPEM, &c.CAKeySealed, &c.SignCertPEM, &c.SignKeySealed, &c.UpdatedBy, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return &MDMConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mdm config: %w", err)
	}
	return &c, nil
}

// SaveMDMConfig writes the whole configuration.
func (s *Store) SaveMDMConfig(ctx context.Context, c MDMConfig) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_config (id, `+mdmConfigColumns+`)
VALUES (1, $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
ON CONFLICT (id) DO UPDATE SET enabled = $1, organization = $2, push_cert_pem = $3, push_key_sealed = $4, push_topic = $5,
	push_expires_at = $6, push_csr_pem = $7, push_csr_key_sealed = $8, ca_cert_pem = $9, ca_key_sealed = $10,
	sign_cert_pem = $11, sign_key_sealed = $12, updated_by = $13, updated_at = now()`,
		c.Enabled, c.Organization, c.PushCertPEM, c.PushKeySealed, c.PushTopic, c.PushExpiresAt, c.PushCSRPEM,
		c.PushCSRKeySealed, c.CACertPEM, c.CAKeySealed, c.SignCertPEM, c.SignKeySealed, c.UpdatedBy)
	if err != nil {
		return fmt.Errorf("save mdm config: %w", err)
	}
	return nil
}

// --- enrollment tokens ------------------------------------------------------

// MDMEnrollToken is an enrollment token's record; the token itself is
// shown once and stored only as a hash.
type MDMEnrollToken struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (s *Store) CreateMDMEnrollToken(ctx context.Context, t MDMEnrollToken, hash string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_enroll_tokens (id, label, token_hash, max_uses, expires_at, created_by)
VALUES ($1,$2,$3,$4,$5,$6)`, t.ID, t.Label, hash, t.MaxUses, t.ExpiresAt, t.CreatedBy)
	if err != nil {
		return fmt.Errorf("create mdm enroll token: %w", err)
	}
	return nil
}

func (s *Store) ListMDMEnrollTokens(ctx context.Context) ([]MDMEnrollToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, label, max_uses, uses, expires_at, revoked_at, created_by, created_at
FROM mdm_enroll_tokens ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list mdm enroll tokens: %w", err)
	}
	defer rows.Close()
	out := []MDMEnrollToken{}
	for rows.Next() {
		var t MDMEnrollToken
		if err := rows.Scan(&t.ID, &t.Label, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.RevokedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeMDMEnrollToken reports whether a live token was revoked.
func (s *Store) RevokeMDMEnrollToken(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE mdm_enroll_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return false, fmt.Errorf("revoke mdm enroll token: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseMDMEnrollToken spends one use of a live token, atomically, and
// returns its id; "" when the token is unknown, revoked, expired or used
// up.
func (s *Store) UseMDMEnrollToken(ctx context.Context, hash string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `UPDATE mdm_enroll_tokens SET uses = uses + 1
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND uses < max_uses RETURNING id`, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("use mdm enroll token: %w", err)
	}
	return id, nil
}

// --- identities -------------------------------------------------------------

// MDMIdentity is one issued device identity certificate.
type MDMIdentity struct {
	Serial      string
	Fingerprint string
	TokenID     string
	UDID        string
	IssuedAt    time.Time
	NotAfter    time.Time
	RevokedAt   *time.Time
}

func (s *Store) CreateMDMIdentity(ctx context.Context, id MDMIdentity) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_identities (serial, fingerprint, token_id, not_after) VALUES ($1,$2,$3,$4)`,
		id.Serial, id.Fingerprint, id.TokenID, id.NotAfter)
	if err != nil {
		return fmt.Errorf("create mdm identity: %w", err)
	}
	return nil
}

// GetMDMIdentity returns the identity, or nil when this server never
// issued it.
func (s *Store) GetMDMIdentity(ctx context.Context, serial string) (*MDMIdentity, error) {
	var id MDMIdentity
	err := s.pool.QueryRow(ctx, `SELECT serial, fingerprint, token_id, udid, issued_at, not_after, revoked_at FROM mdm_identities WHERE serial = $1`, serial).
		Scan(&id.Serial, &id.Fingerprint, &id.TokenID, &id.UDID, &id.IssuedAt, &id.NotAfter, &id.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mdm identity: %w", err)
	}
	return &id, nil
}

// BindMDMIdentity ties an unbound identity to a UDID. It reports false
// when the identity is revoked or already speaks for another device.
func (s *Store) BindMDMIdentity(ctx context.Context, serial, udid string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE mdm_identities SET udid = $2
WHERE serial = $1 AND revoked_at IS NULL AND (udid = '' OR udid = $2)`, serial, udid)
	if err != nil {
		return false, fmt.Errorf("bind mdm identity: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RevokeMDMIdentities revokes every identity bound to a UDID except keep.
func (s *Store) RevokeMDMIdentities(ctx context.Context, udid, keep string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mdm_identities SET revoked_at = now() WHERE udid = $1 AND serial <> $2 AND revoked_at IS NULL`, udid, keep)
	if err != nil {
		return fmt.Errorf("revoke mdm identities: %w", err)
	}
	return nil
}

// --- devices ----------------------------------------------------------------

// MDMDevice is an enrolled (or formerly enrolled) device.
type MDMDevice struct {
	UDID           string          `json:"udid"`
	SerialNumber   string          `json:"serial_number"`
	Model          string          `json:"model"`
	ModelName      string          `json:"model_name"`
	ProductName    string          `json:"product_name"`
	OSVersion      string          `json:"os_version"`
	BuildVersion   string          `json:"build_version"`
	DeviceName     string          `json:"device_name"`
	IdentitySerial string          `json:"-"`
	Topic          string          `json:"-"`
	PushToken      []byte          `json:"-"`
	PushMagic      string          `json:"-"`
	HasPushToken   bool            `json:"has_push_token"`
	AgentID        string          `json:"agent_id"`
	Enrolled       bool            `json:"enrolled"`
	EnrolledAt     time.Time       `json:"enrolled_at"`
	LastSeenAt     time.Time       `json:"last_seen_at"`
	CheckedOutAt   *time.Time      `json:"checked_out_at,omitempty"`
	LastPushAt     *time.Time      `json:"last_push_at,omitempty"`
	LastPushError  string          `json:"last_push_error,omitempty"`
	DeviceInfo     json.RawMessage `json:"device_info,omitempty"`
	DeviceInfoAt   *time.Time      `json:"device_info_at,omitempty"`
	SecurityInfo   json.RawMessage `json:"security_info,omitempty"`
	SecurityInfoAt *time.Time      `json:"security_info_at,omitempty"`
	Apps           json.RawMessage `json:"apps,omitempty"`
	AppsAt         *time.Time      `json:"apps_at,omitempty"`
	Profiles       json.RawMessage `json:"profiles,omitempty"`
	ProfilesAt     *time.Time      `json:"profiles_at,omitempty"`
	// PendingCommands counts commands still waiting for the device.
	PendingCommands int `json:"pending_commands"`
}

const mdmDeviceColumns = `d.udid, d.serial_number, d.model, d.model_name, d.product_name, d.os_version, d.build_version, d.device_name,
	d.identity_serial, d.topic, d.push_token, d.push_magic, d.agent_id, d.enrolled, d.enrolled_at, d.last_seen_at, d.checked_out_at,
	d.last_push_at, d.last_push_error`

func scanMDMDevice(row pgx.Row, full bool) (*MDMDevice, error) {
	var d MDMDevice
	dest := []any{&d.UDID, &d.SerialNumber, &d.Model, &d.ModelName, &d.ProductName, &d.OSVersion, &d.BuildVersion, &d.DeviceName,
		&d.IdentitySerial, &d.Topic, &d.PushToken, &d.PushMagic, &d.AgentID, &d.Enrolled, &d.EnrolledAt, &d.LastSeenAt, &d.CheckedOutAt,
		&d.LastPushAt, &d.LastPushError, &d.PendingCommands}
	if full {
		dest = append(dest, &d.DeviceInfo, &d.DeviceInfoAt, &d.SecurityInfo, &d.SecurityInfoAt, &d.Apps, &d.AppsAt, &d.Profiles, &d.ProfilesAt)
	}
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	d.HasPushToken = len(d.PushToken) > 0 && d.PushMagic != ""
	return &d, nil
}

const mdmPendingCount = `(SELECT count(*) FROM mdm_commands c WHERE c.udid = d.udid AND c.state IN ('queued','sent','not_now'))`

// GetMDMDevice returns the device with its stored command results, or nil.
func (s *Store) GetMDMDevice(ctx context.Context, udid string) (*MDMDevice, error) {
	d, err := scanMDMDevice(s.pool.QueryRow(ctx, `SELECT `+mdmDeviceColumns+`, `+mdmPendingCount+`,
	d.device_info, d.device_info_at, d.security_info, d.security_info_at, d.apps, d.apps_at, d.profiles, d.profiles_at
FROM mdm_devices d WHERE d.udid = $1`, udid), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mdm device: %w", err)
	}
	return d, nil
}

// ListMDMDevices lists devices without their stored results; agentID, when
// set, keeps the ones linked to that endpoint.
func (s *Store) ListMDMDevices(ctx context.Context, agentID string) ([]MDMDevice, error) {
	q := `SELECT ` + mdmDeviceColumns + `, ` + mdmPendingCount + ` FROM mdm_devices d`
	args := []any{}
	if agentID != "" {
		q += ` WHERE d.agent_id = $1`
		args = append(args, agentID)
	}
	rows, err := s.pool.Query(ctx, q+` ORDER BY d.enrolled DESC, lower(d.device_name), d.udid`, args...)
	if err != nil {
		return nil, fmt.Errorf("list mdm devices: %w", err)
	}
	defer rows.Close()
	out := []MDMDevice{}
	for rows.Next() {
		d, err := scanMDMDevice(rows, false)
		if err != nil {
			return nil, fmt.Errorf("scan mdm device: %w", err)
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// MDMAuthenticate records an Authenticate check-in: a new device, or a
// device enrolling again (with a new identity, after which its old ones
// are revoked by the caller). Push credentials are cleared, as Apple
// documents: they come with the TokenUpdate that follows.
func (s *Store) MDMAuthenticate(ctx context.Context, m *mdm.CheckinMessage, identitySerial string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_devices (udid, serial_number, model, model_name, product_name, os_version, build_version,
	device_name, identity_serial, topic, enrolled, enrolled_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, false, now(), now())
ON CONFLICT (udid) DO UPDATE SET serial_number = $2, model = $3, model_name = $4, product_name = $5, os_version = $6,
	build_version = $7, device_name = $8, identity_serial = $9, topic = $10, enrolled = false, push_token = NULL, push_magic = '',
	last_seen_at = now()`,
		m.UDID, m.SerialNumber, m.Model, m.ModelName, m.ProductName, m.OSVersion, m.BuildVersion, m.DeviceName, identitySerial, m.Topic)
	if err != nil {
		return fmt.Errorf("mdm authenticate: %w", err)
	}
	return nil
}

// MDMTokenUpdate stores the push credentials; the first one completes the
// enrollment.
func (s *Store) MDMTokenUpdate(ctx context.Context, udid string, token []byte, pushMagic string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mdm_devices SET push_token = $2, push_magic = $3, last_seen_at = now(),
	enrolled_at = CASE WHEN enrolled THEN enrolled_at ELSE now() END, enrolled = true, checked_out_at = NULL WHERE udid = $1`,
		udid, token, pushMagic)
	if err != nil {
		return fmt.Errorf("mdm token update: %w", err)
	}
	return nil
}

// MDMCheckOut records that the device removed its enrollment. What it had
// not yet been sent will never arrive, so it is cancelled.
func (s *Store) MDMCheckOut(ctx context.Context, udid string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE mdm_devices SET enrolled = false, checked_out_at = now(), push_token = NULL, push_magic = '',
	last_seen_at = now() WHERE udid = $1`, udid); err != nil {
		return fmt.Errorf("mdm check out: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mdm_commands SET state = 'cancelled', finished_at = now(), updated_at = now()
WHERE udid = $1 AND state IN ('queued','not_now')`, udid); err != nil {
		return fmt.Errorf("mdm check out: %w", err)
	}
	return tx.Commit(ctx)
}

// TouchMDMDevice records that the device was heard from.
func (s *Store) TouchMDMDevice(ctx context.Context, udid string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mdm_devices SET last_seen_at = now() WHERE udid = $1`, udid)
	return err
}

// SetMDMDeviceAgent links (or, with "", unlinks) the device's endpoint.
func (s *Store) SetMDMDeviceAgent(ctx context.Context, udid, agentID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mdm_devices SET agent_id = $2 WHERE udid = $1 AND agent_id <> $2`, udid, agentID)
	return err
}

// SetMDMPushResult records the last push attempt.
func (s *Store) SetMDMPushResult(ctx context.Context, udid, pushErr string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mdm_devices SET last_push_at = now(), last_push_error = $2 WHERE udid = $1`, udid, pushErr)
	return err
}

// SetMDMDeviceResult stores a query command's answer on the device:
// kind is the request type. DeviceInformation also refreshes the fields
// the device list shows.
func (s *Store) SetMDMDeviceResult(ctx context.Context, udid, kind string, value json.RawMessage) error {
	var q string
	switch kind {
	case mdm.CmdDeviceInformation:
		q = `UPDATE mdm_devices SET device_info = $2, device_info_at = now(),
	device_name = COALESCE(NULLIF($2::jsonb->>'DeviceName', ''), device_name),
	os_version = COALESCE(NULLIF($2::jsonb->>'OSVersion', ''), os_version),
	build_version = COALESCE(NULLIF($2::jsonb->>'BuildVersion', ''), build_version),
	serial_number = COALESCE(NULLIF($2::jsonb->>'SerialNumber', ''), serial_number) WHERE udid = $1`
	case mdm.CmdSecurityInfo:
		q = `UPDATE mdm_devices SET security_info = $2, security_info_at = now() WHERE udid = $1`
	case mdm.CmdInstalledApplicationList:
		q = `UPDATE mdm_devices SET apps = $2, apps_at = now() WHERE udid = $1`
	case mdm.CmdProfileList:
		q = `UPDATE mdm_devices SET profiles = $2, profiles_at = now() WHERE udid = $1`
	default:
		return fmt.Errorf("no stored result for %s", kind)
	}
	_, err := s.pool.Exec(ctx, q, udid, value)
	return err
}

// DeleteMDMDevice removes the device and its command history, and
// revokes its identities so it cannot come back without enrolling again.
func (s *Store) DeleteMDMDevice(ctx context.Context, udid string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM mdm_devices WHERE udid = $1`, udid)
	if err != nil {
		return false, fmt.Errorf("delete mdm device: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mdm_identities SET revoked_at = now() WHERE udid = $1 AND revoked_at IS NULL`, udid); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, tx.Commit(ctx)
}

// --- commands ---------------------------------------------------------------

// MDMCommand is one command in a device's queue.
type MDMCommand struct {
	UUID          string          `json:"uuid"`
	UDID          string          `json:"udid"`
	RequestType   string          `json:"request_type"`
	Params        json.RawMessage `json:"params"`
	ProfileID     string          `json:"profile_id,omitempty"`
	Payload       []byte          `json:"-"`
	PayloadSealed bool            `json:"-"`
	PINSealed     string          `json:"-"`
	HasPIN        bool            `json:"has_pin"`
	State         string          `json:"state"`
	Deliveries    int             `json:"deliveries"`
	RequestedBy   string          `json:"requested_by"`
	ApprovalID    string          `json:"approval_id,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	SentAt        *time.Time      `json:"sent_at,omitempty"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Result        json.RawMessage `json:"result,omitempty"`
	ErrorChain    json.RawMessage `json:"error_chain"`
}

const mdmCommandColumns = `uuid, udid, request_type, params, profile_id, payload, payload_sealed, pin_sealed, state, deliveries,
	requested_by, approval_id, created_at, sent_at, finished_at, updated_at, result, error_chain`

func scanMDMCommand(row pgx.Row) (*MDMCommand, error) {
	var c MDMCommand
	if err := row.Scan(&c.UUID, &c.UDID, &c.RequestType, &c.Params, &c.ProfileID, &c.Payload, &c.PayloadSealed, &c.PINSealed,
		&c.State, &c.Deliveries, &c.RequestedBy, &c.ApprovalID, &c.CreatedAt, &c.SentAt, &c.FinishedAt, &c.UpdatedAt,
		&c.Result, &c.ErrorChain); err != nil {
		return nil, err
	}
	c.HasPIN = c.PINSealed != ""
	return &c, nil
}

// EnqueueMDMCommand adds a command to its device's queue.
func (s *Store) EnqueueMDMCommand(ctx context.Context, c MDMCommand) error {
	if len(c.Params) == 0 {
		c.Params = json.RawMessage(`{}`)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_commands (uuid, udid, request_type, params, profile_id, payload, payload_sealed,
	pin_sealed, requested_by, approval_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.UUID, c.UDID, c.RequestType, c.Params, c.ProfileID, c.Payload, c.PayloadSealed, c.PINSealed, c.RequestedBy, c.ApprovalID)
	if err != nil {
		return fmt.Errorf("enqueue mdm command: %w", err)
	}
	return nil
}

// GetMDMCommand returns the command, or nil.
func (s *Store) GetMDMCommand(ctx context.Context, uuid string) (*MDMCommand, error) {
	c, err := scanMDMCommand(s.pool.QueryRow(ctx, `SELECT `+mdmCommandColumns+` FROM mdm_commands WHERE uuid = $1`, uuid))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mdm command: %w", err)
	}
	return c, nil
}

// ListMDMCommands is a device's command history, newest first.
func (s *Store) ListMDMCommands(ctx context.Context, udid string, limit int) ([]MDMCommand, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+mdmCommandColumns+` FROM mdm_commands WHERE udid = $1 ORDER BY created_at DESC LIMIT $2`, udid, limit)
	if err != nil {
		return nil, fmt.Errorf("list mdm commands: %w", err)
	}
	defer rows.Close()
	out := []MDMCommand{}
	for rows.Next() {
		c, err := scanMDMCommand(rows)
		if err != nil {
			return nil, fmt.Errorf("scan mdm command: %w", err)
		}
		c.Payload = nil
		out = append(out, *c)
	}
	return out, rows.Err()
}

// MDMIdle applies the start of a new device session to its queue
// (mdm.IdleTransition): deferred commands are offered again, and ones
// delivered without an answer are offered again or, past the limit, failed.
func (s *Store) MDMIdle(ctx context.Context, udid string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT uuid, state, deliveries FROM mdm_commands WHERE udid = $1 AND state IN ('sent','not_now') FOR UPDATE`, udid)
	if err != nil {
		return fmt.Errorf("mdm idle: %w", err)
	}
	type row struct {
		uuid, state string
		deliveries  int
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.uuid, &r.state, &r.deliveries); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range pending {
		next, ok := mdm.IdleTransition(r.state, r.deliveries)
		if !ok {
			continue
		}
		if next == mdm.StateError {
			_, err = tx.Exec(ctx, `UPDATE mdm_commands SET state = $2, finished_at = now(), updated_at = now(),
	error_chain = $3 WHERE uuid = $1`, r.uuid, next, mdmNoAnswerChain)
		} else {
			_, err = tx.Exec(ctx, `UPDATE mdm_commands SET state = $2, updated_at = now() WHERE uuid = $1`, r.uuid, next)
		}
		if err != nil {
			return fmt.Errorf("mdm idle: %w", err)
		}
	}
	return tx.Commit(ctx)
}

var mdmNoAnswerChain = json.RawMessage(fmt.Sprintf(`[{"code":0,"domain":"mustra","description":"delivered %d times without an answer; not sent again"}]`, mdm.MaxDeliveries))

// MDMRecordReport applies a device's report about one of its commands and
// returns the command as it now stands. A report about a command this
// device was never given returns nil; one repeating a finished command's
// outcome returns it unchanged with mdm.ErrAlreadyFinal.
func (s *Store) MDMRecordReport(ctx context.Context, udid, uuid, status string, result, errorChain json.RawMessage) (*MDMCommand, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	c, err := scanMDMCommand(tx.QueryRow(ctx, `SELECT `+mdmCommandColumns+` FROM mdm_commands WHERE uuid = $1 AND udid = $2 FOR UPDATE`, uuid, udid))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mdm report: %w", err)
	}
	next, terr := mdm.ReportTransition(c.State, status)
	if terr != nil {
		return c, terr
	}
	if len(errorChain) == 0 {
		errorChain = json.RawMessage(`[]`)
	}
	var finished any
	if mdm.Final(next) {
		finished = time.Now()
	}
	if _, err := tx.Exec(ctx, `UPDATE mdm_commands SET state = $2, result = COALESCE($3, result), error_chain = $4,
	finished_at = COALESCE($5, finished_at), updated_at = now() WHERE uuid = $1`, uuid, next, nullJSON(result), errorChain, finished); err != nil {
		return nil, fmt.Errorf("mdm report: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	c.State, c.ErrorChain = next, errorChain
	if result != nil {
		c.Result = result
	}
	return c, nil
}

func nullJSON(v json.RawMessage) any {
	if len(v) == 0 {
		return nil
	}
	return v
}

// MDMNextCommand takes the oldest queued command for the device, marks it
// sent and returns it; nil when there is none.
func (s *Store) MDMNextCommand(ctx context.Context, udid string) (*MDMCommand, error) {
	c, err := scanMDMCommand(s.pool.QueryRow(ctx, `UPDATE mdm_commands SET state = 'sent', deliveries = deliveries + 1,
	sent_at = now(), updated_at = now()
WHERE uuid = (SELECT uuid FROM mdm_commands WHERE udid = $1 AND state = 'queued' ORDER BY created_at, uuid LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING `+mdmCommandColumns, udid))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mdm next command: %w", err)
	}
	return c, nil
}

// CancelMDMCommand cancels a command the device has not been sent (or has
// deferred). It reports false when the command is already with the device
// or finished.
func (s *Store) CancelMDMCommand(ctx context.Context, udid, uuid string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE mdm_commands SET state = 'cancelled', finished_at = now(), updated_at = now()
WHERE uuid = $1 AND udid = $2 AND state IN ('queued','not_now')`, uuid, udid)
	if err != nil {
		return false, fmt.Errorf("cancel mdm command: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// ExpireMDMCommands retires commands still waiting after maxAge: a device
// gone that long is not coming back for them, and a lock or erase queued
// a month ago is no longer what anyone decided.
func (s *Store) ExpireMDMCommands(ctx context.Context, maxAge time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE mdm_commands SET state = 'expired', finished_at = now(), updated_at = now()
WHERE state IN ('queued','sent','not_now') AND created_at < $1`, time.Now().Add(-maxAge))
	if err != nil {
		return 0, fmt.Errorf("expire mdm commands: %w", err)
	}
	return tag.RowsAffected(), nil
}

// MDMDevicesToPush lists enrolled devices with a command waiting that
// were last pushed before `before` (or never).
func (s *Store) MDMDevicesToPush(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.udid FROM mdm_devices d
WHERE d.enrolled AND d.push_token IS NOT NULL AND (d.last_push_at IS NULL OR d.last_push_at < $1)
  AND EXISTS (SELECT 1 FROM mdm_commands c WHERE c.udid = d.udid AND c.state = 'queued')
ORDER BY d.last_push_at NULLS FIRST LIMIT 500`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- profile library --------------------------------------------------------

// MDMProfile is a library profile. Content is loaded only by GetMDMProfile.
type MDMProfile struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Identifier   string    `json:"identifier"`
	DisplayName  string    `json:"display_name"`
	Description  string    `json:"description"`
	Organization string    `json:"organization"`
	PayloadTypes []string  `json:"payload_types"`
	Signed       bool      `json:"signed"`
	Size         int       `json:"size"`
	SHA256       string    `json:"sha256"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	Content      []byte    `json:"-"`
}

func (s *Store) CreateMDMProfile(ctx context.Context, p MDMProfile) error {
	if p.PayloadTypes == nil {
		p.PayloadTypes = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO mdm_profiles (id, name, identifier, display_name, description, organization, payload_types,
	signed, content, sha256, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		p.ID, p.Name, p.Identifier, p.DisplayName, p.Description, p.Organization, p.PayloadTypes, p.Signed, p.Content, p.SHA256, p.CreatedBy)
	if err != nil {
		return fmt.Errorf("create mdm profile: %w", err)
	}
	return nil
}

func (s *Store) ListMDMProfiles(ctx context.Context) ([]MDMProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, identifier, display_name, description, organization, payload_types, signed,
	length(content), sha256, created_by, created_at FROM mdm_profiles ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list mdm profiles: %w", err)
	}
	defer rows.Close()
	out := []MDMProfile{}
	for rows.Next() {
		var p MDMProfile
		if err := rows.Scan(&p.ID, &p.Name, &p.Identifier, &p.DisplayName, &p.Description, &p.Organization, &p.PayloadTypes, &p.Signed,
			&p.Size, &p.SHA256, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetMDMProfile returns the profile with its content, or nil.
func (s *Store) GetMDMProfile(ctx context.Context, id string) (*MDMProfile, error) {
	var p MDMProfile
	err := s.pool.QueryRow(ctx, `SELECT id, name, identifier, display_name, description, organization, payload_types, signed,
	length(content), sha256, created_by, created_at, content FROM mdm_profiles WHERE id = $1`, id).Scan(
		&p.ID, &p.Name, &p.Identifier, &p.DisplayName, &p.Description, &p.Organization, &p.PayloadTypes, &p.Signed,
		&p.Size, &p.SHA256, &p.CreatedBy, &p.CreatedAt, &p.Content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mdm profile: %w", err)
	}
	return &p, nil
}

func (s *Store) DeleteMDMProfile(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM mdm_profiles WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete mdm profile: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
