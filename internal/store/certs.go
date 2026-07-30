package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Klice/homepki/internal/store/storedb"
)

// Cert mirrors a row in the certificates table. NULLable columns use
// pointers so callers can distinguish "absent" from "zero value".
type Cert struct {
	ID                string
	Type              string
	ParentID          *string
	SerialNumber      string
	SubjectCN         string
	SubjectO          string
	SubjectOU         string
	SubjectL          string
	SubjectST         string
	SubjectC          string
	SANDNS            []string
	SANIPs            []string
	IsCA              bool
	PathLen           *int
	KeyAlgo           string
	KeyAlgoParams     string
	KeyUsage          []string
	ExtKeyUsage       []string
	NotBefore         time.Time
	NotAfter          time.Time
	DERCert           []byte
	FingerprintSHA256 string
	Status            string
	RevokedAt         *time.Time
	RevocationReason  *int
	ReplacesID        *string
	ReplacedByID      *string
	CreatedAt         time.Time
	// Source distinguishes homepki-issued certs from operator-imported
	// ones (per docs/STORAGE.md §5.3). Always one of "issued" |
	// "imported"; defaults to "issued" so existing callers don't have
	// to set it.
	Source string
}

// CertKey mirrors a row in the cert_keys table. The blobs are AEAD output;
// produce them via crypto.SealPrivateKey.
type CertKey struct {
	CertID      string
	KEKTier     string
	WrappedDEK  []byte
	DEKNonce    []byte
	CipherNonce []byte
	Ciphertext  []byte
}

// ErrCertNotFound is returned by GetCert / GetCertKey when no row exists.
var ErrCertNotFound = errors.New("cert not found")

// ErrSupersedeNotActive is returned when the rotation combinator can't find
// the old cert in 'active' state (e.g. it's already revoked or superseded).
var ErrSupersedeNotActive = errors.New("supersede: old cert not found or not active")

// InsertCert writes the cert and its key bundle in one transaction.
// Either both rows are written or neither is.
func InsertCert(db *sql.DB, c *Cert, k *CertKey) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertCertTx(tx, c, k); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// IssueCertWithToken atomically inserts the cert + key bundle, optionally an
// initial CRL row (per LIFECYCLE.md §6.2 — CAs get an empty CRL on issuance),
// and marks the supplied form token as used.
//
// resultURL is the URL the POST handler 303-redirects to on success; replays
// of the same form_token return that URL via MarkIdemTokenUsed +
// LookupIdemToken in the next request.
//
// initialCRL is nil for leaf issuance and non-nil for CA issuance.
func IssueCertWithToken(db *sql.DB, c *Cert, k *CertKey, initialCRL *CRL, formToken, resultURL string) error {
	if formToken == "" {
		return errors.New("form token required")
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertCertTx(tx, c, k); err != nil {
		return err
	}
	if initialCRL != nil {
		if err := InsertCRL(tx, initialCRL); err != nil {
			return err
		}
	}
	if err := MarkIdemTokenUsed(tx, formToken, resultURL); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func IssueRotationWithToken(db *sql.DB, newCert *Cert, newKey *CertKey, initialCRL *CRL, oldID, formToken, resultURL string) error {
	if formToken == "" {
		return errors.New("form token required")
	}
	if oldID == "" {
		return errors.New("oldID required")
	}
	if newCert == nil {
		return errors.New("newCert required")
	}
	if newCert.ReplacesID == nil {
		return errors.New("newCert.ReplacesID must be set to oldID")
	}
	if *newCert.ReplacesID != oldID {
		return fmt.Errorf("newCert.ReplacesID %q != oldID %q", *newCert.ReplacesID, oldID)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertCertTx(tx, newCert, newKey); err != nil {
		return err
	}
	if initialCRL != nil {
		if err := InsertCRL(tx, initialCRL); err != nil {
			return err
		}
	}
	if err := supersedeOldTx(tx, oldID, newCert.ID); err != nil {
		return err
	}
	if _, err := CopyDeployTargets(tx, oldID, newCert.ID); err != nil {
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

// supersedeOldTx flips the old cert's status to superseded. Refuses to
// clobber a non-active row so rotating an already-revoked cert errors out
// cleanly with ErrSupersedeNotActive.
func supersedeOldTx(tx sqlcDBTX, oldID, newID string) error {
	id := newID
	n, err := storedb.New(tx).SupersedeCert(context.Background(), storedb.SupersedeCertParams{
		ReplacedByID: &id,
		ID:           oldID,
	})
	if err != nil {
		return fmt.Errorf("supersede: %w", err)
	}
	if n == 0 {
		return ErrSupersedeNotActive
	}
	return nil
}

// insertCertTx is the shared body of InsertCert / IssueCertWithToken /
// IssueRotationWithToken. Operates inside a caller-supplied transaction so
// combinators can compose multiple writes atomically.
func insertCertTx(tx sqlcDBTX, c *Cert, k *CertKey) error {
	if c == nil || k == nil {
		return errors.New("cert and key required")
	}
	if c.ID == "" || k.CertID == "" {
		return errors.New("cert.ID and key.CertID required")
	}
	if c.ID != k.CertID {
		return fmt.Errorf("cert.ID %q != key.CertID %q", c.ID, k.CertID)
	}

	q := storedb.New(tx)
	if err := q.InsertCertificate(context.Background(), certInsertParams(c)); err != nil {
		return fmt.Errorf("insert certificates: %w", err)
	}
	if err := q.InsertCertKey(context.Background(), storedb.InsertCertKeyParams{
		CertID:      k.CertID,
		KekTier:     nonEmptyOrDefault(k.KEKTier, "main"),
		WrappedDek:  k.WrappedDEK,
		DekNonce:    k.DEKNonce,
		CipherNonce: k.CipherNonce,
		Ciphertext:  k.Ciphertext,
	}); err != nil {
		return fmt.Errorf("insert cert_keys: %w", err)
	}
	return nil
}

// certInsertParams marshals our Cert into the sqlc-generated params struct.
// JSON columns are encoded here; nil-or-empty conversions for NULLable
// strings happen via nilIfEmpty.
func certInsertParams(c *Cert) storedb.InsertCertificateParams {
	sanDNS, _ := json.Marshal(strSliceOrEmpty(c.SANDNS))
	sanIP, _ := json.Marshal(strSliceOrEmpty(c.SANIPs))
	keyUsage, _ := json.Marshal(strSliceOrEmpty(c.KeyUsage))
	extKeyUsage, _ := json.Marshal(strSliceOrEmpty(c.ExtKeyUsage))

	return storedb.InsertCertificateParams{
		ID:                c.ID,
		Type:              c.Type,
		ParentID:          c.ParentID,
		SerialNumber:      c.SerialNumber,
		SubjectCn:         c.SubjectCN,
		SubjectO:          nilIfEmpty(c.SubjectO),
		SubjectOu:         nilIfEmpty(c.SubjectOU),
		SubjectL:          nilIfEmpty(c.SubjectL),
		SubjectSt:         nilIfEmpty(c.SubjectST),
		SubjectC:          nilIfEmpty(c.SubjectC),
		SanDns:            string(sanDNS),
		SanIp:             string(sanIP),
		IsCa:              boolToInt(c.IsCA),
		PathLenConstraint: intPtrToInt64Ptr(c.PathLen),
		KeyAlgo:           c.KeyAlgo,
		KeyAlgoParams:     nilIfEmpty(c.KeyAlgoParams),
		KeyUsage:          string(keyUsage),
		ExtKeyUsage:       string(extKeyUsage),
		NotBefore:         c.NotBefore.UTC(),
		NotAfter:          c.NotAfter.UTC(),
		DerCert:           c.DERCert,
		FingerprintSha256: c.FingerprintSHA256,
		Status:            nonEmptyOrDefault(c.Status, "active"),
		ReplacesID:        c.ReplacesID,
		Source:            nonEmptyOrDefault(c.Source, "issued"),
	}
}

// GetCert loads a cert row by id. Returns ErrCertNotFound if missing.
func GetCert(db sqlcDBTX, id string) (*Cert, error) {
	row, err := storedb.New(db).GetCertificate(context.Background(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, err
	}
	return certFromRow(row)
}

// GetCertByFingerprint loads a cert row by its SHA-256 fingerprint (the
// hex string we store in fingerprint_sha256). Returns ErrCertNotFound
// if no row matches. Backs the import flow's idempotency check —
// re-uploading the same root cert resolves to the same row instead of
// creating a duplicate.
func GetCertByFingerprint(db sqlcDBTX, fingerprintSHA256 string) (*Cert, error) {
	row, err := storedb.New(db).GetCertByFingerprint(context.Background(), fingerprintSHA256)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, err
	}
	return certFromRow(row)
}

// certFromRow converts a sqlc-generated Certificate to our domain Cert,
// unmarshalling JSON columns and dereffing nullable pointers.
func certFromRow(row storedb.Certificate) (*Cert, error) {
	c := &Cert{
		ID:                row.ID,
		Type:              row.Type,
		ParentID:          row.ParentID,
		SerialNumber:      row.SerialNumber,
		SubjectCN:         row.SubjectCn,
		SubjectO:          derefOrEmpty(row.SubjectO),
		SubjectOU:         derefOrEmpty(row.SubjectOu),
		SubjectL:          derefOrEmpty(row.SubjectL),
		SubjectST:         derefOrEmpty(row.SubjectSt),
		SubjectC:          derefOrEmpty(row.SubjectC),
		IsCA:              row.IsCa != 0,
		PathLen:           int64PtrToIntPtr(row.PathLenConstraint),
		KeyAlgo:           row.KeyAlgo,
		KeyAlgoParams:     derefOrEmpty(row.KeyAlgoParams),
		NotBefore:         row.NotBefore,
		NotAfter:          row.NotAfter,
		DERCert:           row.DerCert,
		FingerprintSHA256: row.FingerprintSha256,
		Status:            row.Status,
		RevokedAt:         row.RevokedAt,
		RevocationReason:  int64PtrToIntPtr(row.RevocationReason),
		ReplacesID:        row.ReplacesID,
		ReplacedByID:      row.ReplacedByID,
		CreatedAt:         row.CreatedAt,
		Source:            row.Source,
	}
	if err := json.Unmarshal([]byte(row.SanDns), &c.SANDNS); err != nil {
		return nil, fmt.Errorf("unmarshal san_dns: %w", err)
	}
	if err := json.Unmarshal([]byte(row.SanIp), &c.SANIPs); err != nil {
		return nil, fmt.Errorf("unmarshal san_ip: %w", err)
	}
	if err := json.Unmarshal([]byte(row.KeyUsage), &c.KeyUsage); err != nil {
		return nil, fmt.Errorf("unmarshal key_usage: %w", err)
	}
	if err := json.Unmarshal([]byte(row.ExtKeyUsage), &c.ExtKeyUsage); err != nil {
		return nil, fmt.Errorf("unmarshal ext_key_usage: %w", err)
	}
	return c, nil
}

// ListCAs returns every root_ca and intermediate_ca row, newest first.
func ListCAs(db sqlcDBTX) ([]*Cert, error) {
	ids, err := storedb.New(db).ListCAs(context.Background())
	if err != nil {
		return nil, err
	}
	return loadByIDs(db, ids)
}

// ListLeaves returns every leaf row, newest first.
func ListLeaves(db sqlcDBTX) ([]*Cert, error) {
	ids, err := storedb.New(db).ListLeaves(context.Background())
	if err != nil {
		return nil, err
	}
	return loadByIDs(db, ids)
}

// GetChain returns the cert and all its ancestors up to the self-signed
// root, in self-first order ([self, parent, ..., root]). Cycle-safe via a
// visited set.
func GetChain(db sqlcDBTX, id string) ([]*Cert, error) {
	chain := []*Cert{}
	seen := map[string]bool{}
	current := id
	for current != "" {
		if seen[current] {
			break
		}
		seen[current] = true
		c, err := GetCert(db, current)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
		if c.ParentID == nil {
			break
		}
		current = *c.ParentID
	}
	return chain, nil
}

func loadByIDs(db sqlcDBTX, ids []string) ([]*Cert, error) {
	out := make([]*Cert, 0, len(ids))
	for _, id := range ids {
		c, err := GetCert(db, id)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// GetCertKey loads the cert_keys row for id. Returns ErrCertNotFound if
// missing — the caller should treat "key gone" the same as "cert gone".
func GetCertKey(db sqlcDBTX, id string) (*CertKey, error) {
	row, err := storedb.New(db).GetCertKeyByID(context.Background(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCertNotFound
	}
	if err != nil {
		return nil, err
	}
	return &CertKey{
		CertID:      row.CertID,
		KEKTier:     row.KekTier,
		WrappedDEK:  row.WrappedDek,
		DEKNonce:    row.DekNonce,
		CipherNonce: row.CipherNonce,
		Ciphertext:  row.Ciphertext,
	}, nil
}

// ---- type-translation helpers ----

func strSliceOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func nonEmptyOrDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func intPtrToInt64Ptr(p *int) *int64 {
	if p == nil {
		return nil
	}
	v := int64(*p)
	return &v
}

func int64PtrToIntPtr(p *int64) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}
