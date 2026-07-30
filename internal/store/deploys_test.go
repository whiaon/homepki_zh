package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedLeaf inserts a parent + leaf so deploy_targets has a valid cert_id to
// reference. Returns the leaf's id.
func seedLeaf(t *testing.T, db sqlcDBTX) string {
	t.Helper()
	parent := sampleCert("parent-id")
	parent.Type = "intermediate_ca"
	parent.ParentID = nil
	parent.IsCA = true
	parent.SubjectCN = "parent"
	require.NoError(t, insertCertTx(db, parent, sampleKey("parent-id")), "insert parent")
	leaf := sampleCert("leaf-id")
	require.NoError(t, insertCertTx(db, leaf, sampleKey("leaf-id")), "insert leaf")
	return "leaf-id"
}

func sampleTarget(id, certID string) *DeployTarget {
	chain := "/etc/ssl/full.pem"
	owner := "root"
	post := "nginx -s reload"
	return &DeployTarget{
		ID:           id,
		CertID:       certID,
		Name:         "nginx",
		CertPath:     "/etc/ssl/cert.pem",
		KeyPath:      "/etc/ssl/key.pem",
		ChainPath:    &chain,
		Mode:         "0640",
		Owner:        &owner,
		Group:        nil,
		PostCommand:  &post,
		AutoOnRotate: true,
	}
}

func TestDeploys_InsertAndGet(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)

	in := sampleTarget("t1", leafID)
	require.NoError(t, InsertDeployTarget(db, in), "InsertDeployTarget")

	got, err := GetDeployTarget(db, "t1")
	require.NoError(t, err, "GetDeployTarget")
	in.CreatedAt = got.CreatedAt
	assert.Equal(t, in.Name, got.Name)
	assert.Equal(t, in.CertPath, got.CertPath)
	assert.True(t, got.AutoOnRotate)
	require.NotNil(t, got.ChainPath)
	assert.Equal(t, "/etc/ssl/full.pem", *got.ChainPath)
	assert.Nil(t, got.LastDeployedAt, "fresh target should have nil LastDeployedAt")
}

func TestDeploys_GetMissing(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := GetDeployTarget(db, "nope")
	assert.ErrorIs(t, err, ErrDeployTargetNotFound)
}

func TestDeploys_Update(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	in := sampleTarget("t1", leafID)
	in.Name = "haproxy"
	in.AutoOnRotate = false
	in.ChainPath = nil
	require.NoError(t, UpdateDeployTarget(db, in), "UpdateDeployTarget")
	got, _ := GetDeployTarget(db, "t1")
	assert.Equal(t, "haproxy", got.Name)
	assert.False(t, got.AutoOnRotate)
	assert.Nil(t, got.ChainPath)
}

func TestDeploys_Update_WrongCertIDIsNotFound(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	in := sampleTarget("t1", "different-cert")
	assert.ErrorIs(t, UpdateDeployTarget(db, in), ErrDeployTargetNotFound, "cross-cert update")
}

func TestDeploys_DeleteIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	require.NoError(t, DeleteDeployTarget(db, "t1", leafID), "first delete")
	// Second delete on the same id is a no-op (per API.md §8.2).
	assert.NoError(t, DeleteDeployTarget(db, "t1", leafID), "replay delete")
	_, err := GetDeployTarget(db, "t1")
	assert.ErrorIs(t, err, ErrDeployTargetNotFound, "after delete")
}

func TestDeploys_List_OrderingAndCertScope(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)

	a := sampleTarget("ta", leafID)
	a.Name = "alpha"
	b := sampleTarget("tb", leafID)
	b.Name = "bravo"
	c := sampleTarget("tc", leafID)
	c.Name = "alpha" // duplicate name on same cert → unique violation
	require.NoError(t, InsertDeployTarget(db, a))
	require.NoError(t, InsertDeployTarget(db, b))
	assert.Error(t, InsertDeployTarget(db, c), "duplicate (cert_id, name) should violate UNIQUE")

	got, err := ListDeployTargets(db, leafID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "alpha", got[0].Name)
	assert.Equal(t, "bravo", got[1].Name)

	// Scoping: a different cert returns nothing.
	other, err := ListDeployTargets(db, "no-such")
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestDeploys_RecordRun_OKAndFailed(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))

	when := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	require.NoError(t, RecordDeployRun(db, "t1", DeployStatusOK, "01ab", "", when))
	got, _ := GetDeployTarget(db, "t1")
	require.NotNil(t, got.LastStatus)
	assert.Equal(t, "ok", *got.LastStatus)
	require.NotNil(t, got.LastDeployedSerial)
	assert.Equal(t, "01ab", *got.LastDeployedSerial)
	assert.Nil(t, got.LastError, "LastError after ok run")
	require.NotNil(t, got.LastDeployedAt)
	assert.True(t, got.LastDeployedAt.Equal(when), "LastDeployedAt: %v", got.LastDeployedAt)

	// Failed run records the error and overwrites the previous status.
	require.NoError(t, RecordDeployRun(db, "t1", DeployStatusFailed, "01ab", "boom", when.Add(time.Hour)))
	got, _ = GetDeployTarget(db, "t1")
	require.NotNil(t, got.LastStatus)
	assert.Equal(t, "failed", *got.LastStatus)
	require.NotNil(t, got.LastError)
	assert.Equal(t, "boom", *got.LastError)
}

func TestDeploys_RecordRun_RejectsBadStatus(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	assert.Error(t, RecordDeployRun(db, "t1", DeployStatus("stale"), "", "", time.Now()),
		"expected error for status=stale (UI-derived only per STORAGE.md §5.6)")
}

func TestDeploys_RecordRun_MissingTarget(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	err := RecordDeployRun(db, "no-such", DeployStatusOK, "01", "", time.Now())
	assert.ErrorIs(t, err, ErrDeployTargetNotFound)
}

func TestDeploys_CreateWithToken_AtomicAndReplay(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	tok, _ := CreateIdemToken(db)
	resultURL := "/certs/" + leafID

	require.NoError(t, CreateDeployTargetWithToken(db, sampleTarget("t1", leafID), tok, resultURL), "first create")
	row, err := LookupIdemToken(db, tok)
	require.NoError(t, err)
	require.NotNil(t, row.ResultURL)
	assert.Equal(t, resultURL, *row.ResultURL)

	// Replay path: caller never reaches CreateDeployTargetWithToken — they
	// see a populated ResultURL on lookup and 303 to it. Sanity check that
	// re-running the combinator now would error (the unique index protects
	// against an out-of-band double-insert).
	err = CreateDeployTargetWithToken(db, sampleTarget("t1-other-id", leafID), tok, resultURL)
	assert.Error(t, err, "re-running combinator on a used token should fail")
}

func TestDeploys_FKCascadeOnCertDelete(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	require.NoError(t, InsertDeployTarget(db, sampleTarget("t1", leafID)))
	// Hard-delete the cert and confirm the target row vanishes via the
	// schema-declared ON DELETE CASCADE.
	_, err := db.Exec("DELETE FROM certificates WHERE id = ?", leafID)
	require.NoError(t, err)
	_, err = GetDeployTarget(db, "t1")
	assert.ErrorIs(t, err, ErrDeployTargetNotFound, "after cert delete")
}

func TestDeploys_CopyDeployTargets(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	src := sampleTarget("t1", leafID)
	require.NoError(t, InsertDeployTarget(db, src))
	when := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, RecordDeployRun(db, "t1", DeployStatusOK, "0a", "", when))

	successor := sampleCert("successor-id")
	successor.SerialNumber = "0b"
	require.NoError(t, insertCertTx(db, successor, sampleKey("successor-id")))

	n, err := CopyDeployTargets(db, leafID, "successor-id")
	require.NoError(t, err, "CopyDeployTargets")
	assert.Equal(t, 1, n)

	copies, err := ListDeployTargets(db, "successor-id")
	require.NoError(t, err)
	require.Len(t, copies, 1)
	got := copies[0]
	assert.NotEqual(t, "t1", got.ID, "copy must get a fresh id")
	assert.Equal(t, "successor-id", got.CertID)
	assert.Equal(t, src.Name, got.Name)
	assert.Equal(t, src.CertPath, got.CertPath)
	assert.Equal(t, src.KeyPath, got.KeyPath)
	require.NotNil(t, got.ChainPath)
	assert.Equal(t, *src.ChainPath, *got.ChainPath)
	assert.Equal(t, src.Mode, got.Mode)
	require.NotNil(t, got.Owner)
	assert.Equal(t, *src.Owner, *got.Owner)
	assert.Nil(t, got.Group)
	require.NotNil(t, got.PostCommand)
	assert.Equal(t, *src.PostCommand, *got.PostCommand)
	assert.True(t, got.AutoOnRotate)
	require.NotNil(t, got.LastDeployedSerial)
	assert.Equal(t, "0a", *got.LastDeployedSerial, "run state should describe what is on disk")
	require.NotNil(t, got.LastStatus)
	assert.Equal(t, "ok", *got.LastStatus)

	orig, err := GetDeployTarget(db, "t1")
	require.NoError(t, err)
	assert.Equal(t, leafID, orig.CertID, "source target must stay on the old cert")
}

func TestDeploys_CopyDeployTargets_NoSources(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	leafID := seedLeaf(t, db)
	n, err := CopyDeployTargets(db, leafID, "successor-id")
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestDeploys_CopyDeployTargets_RequiresBothIDs(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, Migrate(db))
	_, err := CopyDeployTargets(db, "", "successor-id")
	assert.Error(t, err)
	_, err = CopyDeployTargets(db, "leaf-id", "")
	assert.Error(t, err)
}
