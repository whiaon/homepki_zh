package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Klice/homepki/internal/store/storedb"
)

// DeployStatus is the value stored in deploy_targets.last_status. Per
// STORAGE.md §5.6 the runner only ever writes "ok" or "failed"; "stale" is
// derived in the UI by comparing last_deployed_serial to the cert's current
// serial.
type DeployStatus string

const (
	DeployStatusOK     DeployStatus = "ok"
	DeployStatusFailed DeployStatus = "failed"
)

// ErrDeployTargetNotFound is returned by GetDeployTarget when no row exists,
// and by UpdateDeployTarget / DeleteDeployTarget / RecordDeployRun when the
// (id, cert_id) tuple doesn't match a row.
var ErrDeployTargetNotFound = errors.New("deploy target not found")

// DeployTarget mirrors a row in deploy_targets.
type DeployTarget struct {
	ID                 string
	CertID             string
	Name               string
	CertPath           string
	KeyPath            string
	ChainPath          *string
	Mode               string
	Owner              *string
	Group              *string
	PostCommand        *string
	AutoOnRotate       bool
	LastDeployedAt     *time.Time
	LastDeployedSerial *string
	LastStatus         *string
	LastError          *string
	CreatedAt          time.Time
}

// NewDeployTargetID returns a fresh UUIDv4 for a deploy_targets row.
func NewDeployTargetID() string {
	return NewCertID() // both columns are TEXT (UUID); reuse the generator.
}

// InsertDeployTarget creates a row from the operator-supplied configuration.
// Caller is responsible for setting t.ID and t.CertID.
func InsertDeployTarget(db sqlcDBTX, t *DeployTarget) error {
	if t == nil {
		return errors.New("target required")
	}
	if t.ID == "" {
		return errors.New("ID required")
	}
	if t.CertID == "" {
		return errors.New("CertID required")
	}
	if err := storedb.New(db).InsertDeployTarget(context.Background(), insertParams(t)); err != nil {
		return err
	}
	return nil
}

// CreateDeployTargetWithToken inserts the target and atomically marks the
// form token used. Replays return resultURL via MarkIdemTokenUsed +
// LookupIdemToken in the next request.
func CreateDeployTargetWithToken(db *sql.DB, t *DeployTarget, formToken, resultURL string) error {
	if formToken == "" {
		return errors.New("form token required")
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := InsertDeployTarget(tx, t); err != nil {
		return err
	}
	if err := MarkIdemTokenUsed(tx, formToken, resultURL); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func CopyDeployTargets(db sqlcDBTX, fromCertID, toCertID string) (int, error) {
	if fromCertID == "" || toCertID == "" {
		return 0, errors.New("fromCertID and toCertID required")
	}
	sources, err := ListDeployTargets(db, fromCertID)
	if err != nil {
		return 0, fmt.Errorf("list source targets: %w", err)
	}
	q := storedb.New(db)
	for _, t := range sources {
		if err := q.InsertDeployTargetWithRunState(context.Background(), storedb.InsertDeployTargetWithRunStateParams{
			ID:                 NewDeployTargetID(),
			CertID:             toCertID,
			Name:               t.Name,
			CertPath:           t.CertPath,
			KeyPath:            t.KeyPath,
			ChainPath:          t.ChainPath,
			Mode:               t.Mode,
			Owner:              t.Owner,
			Group:              t.Group,
			PostCommand:        t.PostCommand,
			AutoOnRotate:       boolToInt(t.AutoOnRotate),
			LastDeployedAt:     t.LastDeployedAt,
			LastDeployedSerial: t.LastDeployedSerial,
			LastStatus:         t.LastStatus,
			LastError:          t.LastError,
		}); err != nil {
			return 0, fmt.Errorf("copy target %q: %w", t.Name, err)
		}
	}
	return len(sources), nil
}

// UpdateDeployTarget overwrites every editable column on the (id, cert_id)
// tuple. Returns ErrDeployTargetNotFound if no such row exists. Atomic at
// the row level — a failed rename in the runner won't leave the metadata
// half-updated.
func UpdateDeployTarget(db sqlcDBTX, t *DeployTarget) error {
	if t == nil {
		return errors.New("target required")
	}
	if t.ID == "" {
		return errors.New("ID required")
	}
	if t.CertID == "" {
		return errors.New("CertID required")
	}
	n, err := storedb.New(db).UpdateDeployTarget(context.Background(), updateParams(t))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeployTargetNotFound
	}
	return nil
}

// UpdateDeployTargetWithToken updates the row and atomically marks the form
// token used. For edit replays the next request returns resultURL via
// MarkIdemTokenUsed.
func UpdateDeployTargetWithToken(db *sql.DB, t *DeployTarget, formToken, resultURL string) error {
	if formToken == "" {
		return errors.New("form token required")
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := UpdateDeployTarget(tx, t); err != nil {
		return err
	}
	if err := MarkIdemTokenUsed(tx, formToken, resultURL); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// GetDeployTarget loads a single row by id. Returns ErrDeployTargetNotFound
// if missing.
func GetDeployTarget(db sqlcDBTX, id string) (*DeployTarget, error) {
	row, err := storedb.New(db).GetDeployTarget(context.Background(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeployTargetNotFound
	}
	if err != nil {
		return nil, err
	}
	return targetFromRow(row), nil
}

// ListDeployTargets returns every target attached to a cert, ordered by
// name then created_at to keep the cert detail page stable across renders.
func ListDeployTargets(db sqlcDBTX, certID string) ([]*DeployTarget, error) {
	rows, err := storedb.New(db).ListDeployTargetsByCertID(context.Background(), certID)
	if err != nil {
		return nil, err
	}
	out := make([]*DeployTarget, 0, len(rows))
	for _, r := range rows {
		out = append(out, targetFromRow(r))
	}
	return out, nil
}

// DeleteDeployTarget removes the (id, cert_id) row. Per API.md §8.2 this is
// idempotent — a no-op when the row is already gone returns nil, not
// ErrDeployTargetNotFound.
func DeleteDeployTarget(db sqlcDBTX, id, certID string) error {
	_, err := storedb.New(db).DeleteDeployTarget(context.Background(), storedb.DeleteDeployTargetParams{
		ID:     id,
		CertID: certID,
	})
	if err != nil {
		return err
	}
	return nil
}

// RecordDeployRun writes the outcome of a single target run. errMsg is the
// empty string on success; on failure it's a short human-readable cause.
// Per STORAGE.md §5.6 last_status is constrained to "ok"/"failed" only.
func RecordDeployRun(db sqlcDBTX, id string, status DeployStatus, serial, errMsg string, when time.Time) error {
	if status != DeployStatusOK && status != DeployStatusFailed {
		return fmt.Errorf("invalid status %q", status)
	}
	statusStr := string(status)
	var serialPtr, errPtr *string
	if serial != "" {
		serialPtr = &serial
	}
	if errMsg != "" {
		errPtr = &errMsg
	}
	n, err := storedb.New(db).RecordDeployRun(context.Background(), storedb.RecordDeployRunParams{
		LastDeployedAt:     &when,
		LastDeployedSerial: serialPtr,
		LastStatus:         &statusStr,
		LastError:          errPtr,
		ID:                 id,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeployTargetNotFound
	}
	return nil
}

// ---- helpers ----

func insertParams(t *DeployTarget) storedb.InsertDeployTargetParams {
	return storedb.InsertDeployTargetParams{
		ID:           t.ID,
		CertID:       t.CertID,
		Name:         t.Name,
		CertPath:     t.CertPath,
		KeyPath:      t.KeyPath,
		ChainPath:    t.ChainPath,
		Mode:         t.Mode,
		Owner:        t.Owner,
		Group:        t.Group,
		PostCommand:  t.PostCommand,
		AutoOnRotate: boolToInt(t.AutoOnRotate),
	}
}

func updateParams(t *DeployTarget) storedb.UpdateDeployTargetParams {
	return storedb.UpdateDeployTargetParams{
		Name:         t.Name,
		CertPath:     t.CertPath,
		KeyPath:      t.KeyPath,
		ChainPath:    t.ChainPath,
		Mode:         t.Mode,
		Owner:        t.Owner,
		Group:        t.Group,
		PostCommand:  t.PostCommand,
		AutoOnRotate: boolToInt(t.AutoOnRotate),
		ID:           t.ID,
		CertID:       t.CertID,
	}
}

func targetFromRow(r storedb.DeployTarget) *DeployTarget {
	return &DeployTarget{
		ID:                 r.ID,
		CertID:             r.CertID,
		Name:               r.Name,
		CertPath:           r.CertPath,
		KeyPath:            r.KeyPath,
		ChainPath:          r.ChainPath,
		Mode:               r.Mode,
		Owner:              r.Owner,
		Group:              r.Group,
		PostCommand:        r.PostCommand,
		AutoOnRotate:       r.AutoOnRotate != 0,
		LastDeployedAt:     r.LastDeployedAt,
		LastDeployedSerial: r.LastDeployedSerial,
		LastStatus:         r.LastStatus,
		LastError:          r.LastError,
		CreatedAt:          r.CreatedAt,
	}
}
