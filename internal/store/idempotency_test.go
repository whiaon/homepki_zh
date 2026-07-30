package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAndLookup_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))

	tok, err := CreateIdemToken(db)
	require.NoError(t, err, "CreateIdemToken")
	assert.Len(t, tok, 64, "token length: want 64 (32 bytes hex)")

	got, err := LookupIdemToken(db, tok)
	require.NoError(t, err, "LookupIdemToken")
	assert.Equal(t, tok, got.Token)
	assert.Nil(t, got.UsedAt, "fresh token should have nil UsedAt")
	assert.Nil(t, got.ResultURL, "fresh token should have nil ResultURL")
	assert.True(t, got.ExpiresAt.After(got.CreatedAt),
		"ExpiresAt %v should be after CreatedAt %v", got.ExpiresAt, got.CreatedAt)
}

func TestCreateUniqueness(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	a, err := CreateIdemToken(db)
	require.NoError(t, err)
	b, err := CreateIdemToken(db)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "two consecutive CreateIdemToken calls returned the same token")
}

func TestLookup_MissingReturnsSentinel(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := LookupIdemToken(db, "no-such-token")
	assert.ErrorIs(t, err, ErrIdemTokenNotFound)
	_, err = LookupIdemToken(db, "")
	assert.ErrorIs(t, err, ErrIdemTokenNotFound, "empty token")
}

func TestMarkUsed_RoundTripAndIdempotency(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	require.NoError(t, MarkIdemTokenUsed(db, tok, "/certs/abc"), "MarkIdemTokenUsed")

	got, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.NotNil(t, got.UsedAt, "UsedAt should be set after MarkIdemTokenUsed")
	require.NotNil(t, got.ResultURL)
	assert.Equal(t, "/certs/abc", *got.ResultURL)

	// A second mark on the same token must fail — the WHERE clause
	// "used_at IS NULL" filters it out, so RowsAffected = 0.
	err = MarkIdemTokenUsed(db, tok, "/somewhere/else")
	assert.ErrorIs(t, err, ErrIdemTokenNotFound, "second mark")

	// And the original ResultURL is preserved.
	got, err = LookupIdemToken(db, tok)
	require.NoError(t, err)
	require.NotNil(t, got.ResultURL)
	assert.Equal(t, "/certs/abc", *got.ResultURL, "after second mark, ResultURL was overwritten")
}

func TestMarkUsed_UnknownToken(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	err := MarkIdemTokenUsed(db, "no-such", "/x")
	assert.ErrorIs(t, err, ErrIdemTokenNotFound)
	err = MarkIdemTokenUsed(db, "", "/x")
	assert.ErrorIs(t, err, ErrIdemTokenNotFound, "empty token")
}

func TestIssueCertWithToken_AtomicSuccess(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	c := sampleCert("issued-id")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	k := sampleKey("issued-id")

	require.NoError(t, IssueCertWithToken(db, c, k, nil, tok, "/certs/issued-id"), "IssueCertWithToken")

	// Cert and key both written.
	_, err = GetCert(db, "issued-id")
	assert.NoError(t, err, "cert row missing")
	_, err = GetCertKey(db, "issued-id")
	assert.NoError(t, err, "key row missing")
	// Token marked used.
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.NotNil(t, row.UsedAt)
	require.NotNil(t, row.ResultURL)
	assert.Equal(t, "/certs/issued-id", *row.ResultURL)
}

func TestIssueCertWithToken_RollsBackOnFKViolation(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)
	// Bad parent_id triggers FK violation inside insertCertTx.
	c := sampleCert("orphan")
	c.ParentID = ptrStr("does-not-exist")
	k := sampleKey("orphan")

	assert.Error(t, IssueCertWithToken(db, c, k, nil, tok, "/x"), "expected FK violation error")
	// All three rows must be absent.
	_, err = GetCert(db, "orphan")
	assert.ErrorIs(t, err, ErrCertNotFound, "cert row should not have been written")
	_, err = GetCertKey(db, "orphan")
	assert.ErrorIs(t, err, ErrCertNotFound, "key row should not have been written")
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.Nil(t, row.UsedAt, "token should not have been marked used after rollback")
}

func TestIssueCertWithToken_WithInitialCRL(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	c := sampleCert("ca-id")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	k := sampleKey("ca-id")

	now := time.Now()
	crl := &CRL{
		IssuerCertID: "ca-id",
		CRLNumber:    1,
		ThisUpdate:   now,
		NextUpdate:   now.Add(7 * 24 * time.Hour),
		DER:          []byte{0xCA, 0xFE},
	}

	require.NoError(t, IssueCertWithToken(db, c, k, crl, tok, "/certs/ca-id"), "IssueCertWithToken")

	// All four states must be visible after commit.
	_, err = GetCert(db, "ca-id")
	assert.NoError(t, err, "cert row missing")
	_, err = GetCertKey(db, "ca-id")
	assert.NoError(t, err, "key row missing")
	got, err := GetLatestCRL(db, "ca-id")
	if assert.NoError(t, err, "crl row missing") {
		assert.Equal(t, int64(1), got.CRLNumber)
	}
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.NotNil(t, row.UsedAt, "token should have been marked used")
}

func TestIssueCertWithToken_InitialCRLRollsBackOnFailure(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	// Mismatched issuer_cert_id will fail the FK on crls.issuer_cert_id
	// when the cert hasn't been inserted under that id.
	c := sampleCert("real-ca")
	c.Type = "root_ca"
	c.IsCA = true
	c.ParentID = nil
	crl := &CRL{
		IssuerCertID: "wrong-ca",
		CRLNumber:    1,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		DER:          []byte{0x00},
	}
	require.Error(t, IssueCertWithToken(db, c, sampleKey("real-ca"), crl, tok, "/x"),
		"expected FK violation")
	// Cert, key, and token must all be in their pre-call state.
	_, err = GetCert(db, "real-ca")
	assert.ErrorIs(t, err, ErrCertNotFound, "cert row should not have been written")
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.Nil(t, row.UsedAt, "token should not have been marked used after rollback")
}

func TestIssueRotationWithToken_AtomicSuccess(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	// New cert (a successor root) with replaces_id pointing at the existing root.
	newCert := makeCert("rotated-root", "root_ca", nil, "Replacement Root")
	rid := rootID
	newCert.ReplacesID = &rid
	newKey := sampleKey("rotated-root")

	require.NoError(t, IssueRotationWithToken(db, newCert, newKey, nil, rootID, tok, "/certs/rotated-root"),
		"IssueRotationWithToken")

	// Old cert is now superseded with replaced_by_id forward-link.
	old, err := GetCert(db, rootID)
	require.NoError(t, err)
	assert.Equal(t, "superseded", old.Status, "old status")
	require.NotNil(t, old.ReplacedByID)
	assert.Equal(t, "rotated-root", *old.ReplacedByID)

	// New cert is active with replaces_id back-link.
	got, err := GetCert(db, "rotated-root")
	require.NoError(t, err)
	assert.Equal(t, "active", got.Status, "new status")
	require.NotNil(t, got.ReplacesID)
	assert.Equal(t, rootID, *got.ReplacesID)

	// Token is marked.
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.NotNil(t, row.UsedAt, "token should have been marked used")
}

func TestIssueRotationWithToken_CopiesDeployTargets(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, interID, leafID := seed(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	newCert := makeCert("rotated-leaf", "leaf", &interID, "leaf.test")
	newCert.SerialNumber = "0f"
	lid := leafID
	newCert.ReplacesID = &lid

	require.NoError(t, IssueRotationWithToken(db, newCert, sampleKey("rotated-leaf"), nil, leafID, tok, "/certs/rotated-leaf"))

	copies, err := ListDeployTargets(db, "rotated-leaf")
	require.NoError(t, err)
	require.Len(t, copies, 1, "successor did not inherit deploy targets")
	assert.Equal(t, "nginx", copies[0].Name)

	kept, err := ListDeployTargets(db, leafID)
	require.NoError(t, err)
	assert.Len(t, kept, 1, "superseded cert should keep its own targets")
}

func TestIssueRotationWithToken_RefusesNonActiveOld(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, _, leafID := seed(t, db)
	// Pre-revoke the leaf — rotation must refuse.
	_, err := MarkRevoked(db, leafID, 1, time.Now())
	require.NoError(t, err)
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)

	newCert := makeCert("would-be-replacement", "leaf", ptrStr("inter-id"), "leaf2.test")
	newCert.SerialNumber = "02" // distinct from seed leaf to avoid UNIQUE(parent_id, serial)
	lid := leafID
	newCert.ReplacesID = &lid

	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))

	err = IssueRotationWithToken(db, newCert, sampleKey("would-be-replacement"), nil, leafID, tok, "/x")
	assert.ErrorIs(t, err, ErrSupersedeNotActive)
	copies, err := ListDeployTargets(db, "would-be-replacement")
	require.NoError(t, err)
	assert.Empty(t, copies, "no targets should be copied when the rotation rolls back")
	// And nothing else changed: token unmarked, new cert absent.
	_, err = GetCert(db, "would-be-replacement")
	assert.ErrorIs(t, err, ErrCertNotFound, "new cert should not have been written")
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	assert.Nil(t, row.UsedAt, "token should not have been marked used")
}

func TestIssueRotationWithToken_RejectsBadInputs(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	rootID, _, _ := seed(t, db)
	tok, _ := CreateIdemToken(db)

	rid := rootID
	good := makeCert("new-root", "root_ca", nil, "X")
	good.ReplacesID = &rid

	cases := []struct {
		name string
		fn   func() error
	}{
		{"empty token", func() error {
			return IssueRotationWithToken(db, good, sampleKey("new-root"), nil, rootID, "", "/x")
		}},
		{"empty oldID", func() error {
			return IssueRotationWithToken(db, good, sampleKey("new-root"), nil, "", tok, "/x")
		}},
		{"missing replaces_id", func() error {
			bad := makeCert("new-root", "root_ca", nil, "X")
			// no ReplacesID set
			return IssueRotationWithToken(db, bad, sampleKey("new-root"), nil, rootID, tok, "/x")
		}},
		{"replaces_id mismatch", func() error {
			bad := makeCert("new-root", "root_ca", nil, "X")
			other := "other-id"
			bad.ReplacesID = &other
			return IssueRotationWithToken(db, bad, sampleKey("new-root"), nil, rootID, tok, "/x")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.fn())
		})
	}
}

func TestIssueCertWithToken_RejectsEmptyToken(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	c := sampleCert("x")
	c.Type = "root_ca"
	c.ParentID = nil
	assert.Error(t, IssueCertWithToken(db, c, sampleKey("x"), nil, "", "/x"),
		"expected error on empty form token")
}

func TestCleanupExpired(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	// Make the just-created token "expired" by setting expires_at into the
	// past directly. CreateIdemToken won't do that itself.
	tok, err := CreateIdemToken(db)
	require.NoError(t, err)
	_, err = db.Exec(
		`UPDATE idempotency_tokens SET expires_at = datetime('now', '-1 hour') WHERE token = ?`,
		tok,
	)
	require.NoError(t, err)

	n, err := CleanupExpiredIdemTokens(db)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "deleted")
	_, err = LookupIdemToken(db, tok)
	assert.ErrorIs(t, err, ErrIdemTokenNotFound, "after cleanup")
}
