package web

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Klice/homepki/internal/store"
)

// deployFixture issues a leaf chain and returns a primed client + IDs.
// Mirrors downloadFixture.
func deployFixture(t *testing.T) (srv *Server, c *clientLite, leafID string, dir string) {
	t.Helper()
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c = newClient(t, srv)
	installSession(t, srv, c)
	_, _, leafID = issueChain(t, c)
	dir = t.TempDir()
	c.get("/certs/" + leafID) // prime CSRF
	return
}

// createTarget POSTs a new-target form and returns the new target id by
// reading it back from the DB. POST handler 303s to the cert detail page,
// not the target — so we list and grab the only one.
func createTarget(t *testing.T, c *clientLite, srv *Server, leafID string, override url.Values) string {
	t.Helper()
	form := url.Values{
		"name":      {"nginx"},
		"cert_path": {"/tmp/homepki-test-cert.pem"},
		"key_path":  {"/tmp/homepki-test-key.pem"},
		"mode":      {"0640"},
	}
	for k, v := range override {
		form[k] = v
	}
	w := c.get("/certs/" + leafID + "/deploy/new")
	require.Equal(t, http.StatusOK, w.Code, "GET deploy/new")
	form.Set("form_token", extractFormToken(t, w.Body.String()))
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	require.Equal(t, http.StatusSeeOther, w.Code, "POST deploy/new")
	targets, err := store.ListDeployTargets(srv.db, leafID)
	require.NoError(t, err, "ListDeployTargets")
	require.NotEmpty(t, targets, "no targets after create")
	return targets[len(targets)-1].ID
}

// ============== create ==============

func TestDeploy_CreateAndAppearOnDetail(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "out.crt")
	keyPath := filepath.Join(dir, "out.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"nginx"},
		"cert_path": {certPath},
		"key_path":  {keyPath},
	})

	w := c.get("/certs/" + leafID)
	body := w.Body.String()
	for _, want := range []string{
		"nginx",
		certPath,
		`/certs/` + leafID + `/deploy/` + tid + `/run`,
		`/certs/` + leafID + `/deploy/` + tid + `/edit`,
		`/certs/` + leafID + `/deploy/` + tid + `/delete`,
	} {
		assert.Contains(t, body, want)
	}
}

func TestDeploy_CreateRejectsRelativePath(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	_ = srv

	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/"+leafID+"/deploy/new", url.Values{
		"name":       {"bad"},
		"cert_path":  {"relative/cert.pem"},
		"key_path":   {"/abs/key.pem"},
		"mode":       {"0640"},
		"form_token": {formTok},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "absolute")
}

func TestDeploy_CreateRejectsBadMode(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	_ = srv
	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	w = c.postForm("/certs/"+leafID+"/deploy/new", url.Values{
		"name":       {"bad"},
		"cert_path":  {"/abs/cert.pem"},
		"key_path":   {"/abs/key.pem"},
		"mode":       {"not-octal"},
		"form_token": {formTok},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeploy_CreateOnNonLeafIs404(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	installSession(t, srv, c)
	rootID, _, _ := issueChain(t, c)

	w := c.get("/certs/" + rootID + "/deploy/new")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeploy_CreateFormTokenReplay(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")

	w := c.get("/certs/" + leafID + "/deploy/new")
	formTok := extractFormToken(t, w.Body.String())
	form := url.Values{
		"name":       {"replay"},
		"cert_path":  {cert},
		"key_path":   {key},
		"mode":       {"0640"},
		"form_token": {formTok},
	}
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	require.Equal(t, http.StatusSeeOther, w.Code, "first")
	first := w.Header().Get("Location")

	// Replay same form_token → 303 to the originally-set result_url, no second row.
	w = c.postForm("/certs/"+leafID+"/deploy/new", form)
	assert.Equal(t, http.StatusSeeOther, w.Code, "replay status")
	assert.Equal(t, first, w.Header().Get("Location"), "replay location")
	targets, _ := store.ListDeployTargets(srv.db, leafID)
	assert.Len(t, targets, 1, "targets after replay")
}

// ============== edit ==============

func TestDeploy_EditUpdatesRow(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path": {filepath.Join(dir, "old.crt")},
		"key_path":  {filepath.Join(dir, "old.key")},
	})

	w := c.get("/certs/" + leafID + "/deploy/" + tid + "/edit")
	require.Equal(t, http.StatusOK, w.Code, "GET edit")
	formTok := extractFormToken(t, w.Body.String())
	newCert := filepath.Join(dir, "new.crt")
	w = c.postForm("/certs/"+leafID+"/deploy/"+tid+"/edit", url.Values{
		"name":           {"haproxy"},
		"cert_path":      {newCert},
		"key_path":       {filepath.Join(dir, "new.key")},
		"mode":           {"0600"},
		"auto_on_rotate": {"1"},
		"form_token":     {formTok},
	})
	require.Equal(t, http.StatusSeeOther, w.Code, "POST edit")
	got, err := store.GetDeployTarget(srv.db, tid)
	require.NoError(t, err)
	assert.Equal(t, "haproxy", got.Name)
	assert.Equal(t, newCert, got.CertPath)
	assert.True(t, got.AutoOnRotate)
	assert.Equal(t, "0600", got.Mode)
}

func TestDeploy_EditCrossCertIs404(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)
	// Try editing under a different (non-existent) cert id.
	w := c.get("/certs/no-such/deploy/" + tid + "/edit")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============== delete ==============

func TestDeploy_DeleteRemovesAndIsIdempotent(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/delete", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, "first delete")
	_, err := store.GetDeployTarget(srv.db, tid)
	assert.Error(t, err, "target still exists after delete")
	// Replay → 303, no error.
	w = c.postForm("/certs/"+leafID+"/deploy/"+tid+"/delete", url.Values{})
	assert.Equal(t, http.StatusSeeOther, w.Code, "replay")
}

// ============== run ==============

func TestDeploy_RunOneWritesFiles(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "out.crt")
	keyPath := filepath.Join(dir, "out.key")
	chainPath := filepath.Join(dir, "fullchain.crt")
	flag := filepath.Join(dir, "ran")

	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":    {certPath},
		"key_path":     {keyPath},
		"chain_path":   {chainPath},
		"post_command": {"touch " + flag},
	})

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, "run")

	// Cert file: parses as a real X.509 with our CN.
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err, "cert file")
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "cert PEM did not decode")
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "parse cert")
	assert.Equal(t, "revoke.leaf.test", parsed.Subject.CommonName, "cert CN")
	// Key file: PKCS#8 PEM.
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err, "key file")
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock, "key block")
	assert.Equal(t, "PRIVATE KEY", keyBlock.Type, "key block type")
	_, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	assert.NoError(t, err, "parse pkcs8")
	// Fullchain: leaf + intermediate.
	chain, _ := os.ReadFile(chainPath)
	assert.Equal(t, 2, strings.Count(string(chain), "-----BEGIN CERTIFICATE-----"), "fullchain block count")
	// post_command ran.
	_, err = os.Stat(flag)
	assert.NoError(t, err, "post_command did not run")
	// Row updated.
	got, _ := store.GetDeployTarget(srv.db, tid)
	require.NotNil(t, got.LastStatus, "last_status nil")
	assert.Equal(t, "ok", *got.LastStatus, "last_status")
}

func TestDeploy_RunOneRecordsFailure(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":    {filepath.Join(dir, "out.crt")},
		"key_path":     {filepath.Join(dir, "out.key")},
		"post_command": {"exit 1"},
	})
	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, "run")
	got, _ := store.GetDeployTarget(srv.db, tid)
	require.NotNil(t, got.LastStatus, "last_status nil")
	assert.Equal(t, "failed", *got.LastStatus, "last_status")
	require.NotNil(t, got.LastError, "last_error nil")
	assert.Contains(t, *got.LastError, "post_command", "last_error")
}

func TestDeploy_RunAllSequential(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	a := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"a"},
		"cert_path": {filepath.Join(dir, "a.crt")},
		"key_path":  {filepath.Join(dir, "a.key")},
	})
	b := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"b"},
		"cert_path": {filepath.Join(dir, "b.crt")},
		"key_path":  {filepath.Join(dir, "b.key")},
	})

	w := c.postForm("/certs/"+leafID+"/deploy", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, "run-all")
	for _, id := range []string{a, b} {
		got, _ := store.GetDeployTarget(srv.db, id)
		require.NotNil(t, got.LastStatus, "target %s status nil", id)
		assert.Equal(t, "ok", *got.LastStatus, "target %s status", id)
	}
	for _, p := range []string{filepath.Join(dir, "a.crt"), filepath.Join(dir, "b.crt")} {
		_, err := os.Stat(p)
		assert.NoError(t, err, "file %s not written", p)
	}
}

func TestDeploy_RunWhenLockedRedirectsToUnlock(t *testing.T) {
	srv, c, leafID, _ := deployFixture(t)
	tid := createTarget(t, c, srv, leafID, nil)
	srv.keystore.Lock()

	w := c.postForm("/certs/"+leafID+"/deploy/"+tid+"/run", url.Values{})
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

// ============== auto on rotate ==============

func TestDeploy_AutoOnRotateFiresAfterRotation(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "auto.crt")
	keyPath := filepath.Join(dir, "auto.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":      {certPath},
		"key_path":       {keyPath},
		"auto_on_rotate": {"1"},
	})

	newID := mustIssue(t, c, "/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
	})

	require.NotEqual(t, leafID, newID, "rotated cert has same id")

	newTargets, err := store.ListDeployTargets(srv.db, newID)
	require.NoError(t, err)
	require.Len(t, newTargets, 1, "successor did not inherit the deploy target")
	inherited := newTargets[0]
	assert.NotEqual(t, tid, inherited.ID, "inherited target reused the old row id")
	assert.Equal(t, certPath, inherited.CertPath)
	assert.Equal(t, keyPath, inherited.KeyPath)
	assert.True(t, inherited.AutoOnRotate, "auto_on_rotate not carried over")

	newCert, err := store.GetCert(srv.db, newID)
	require.NoError(t, err)
	require.NotNil(t, inherited.LastStatus, "auto-on-rotate did not run on the successor")
	assert.Equal(t, "ok", *inherited.LastStatus)
	require.NotNil(t, inherited.LastDeployedSerial)
	assert.Equal(t, newCert.SerialNumber, *inherited.LastDeployedSerial, "deployed serial is not the successor's")

	writtenPEM, err := os.ReadFile(certPath)
	require.NoError(t, err, "cert not written")
	block, _ := pem.Decode(writtenPEM)
	require.NotNil(t, block)
	assert.Equal(t, newCert.DERCert, block.Bytes, "deployed cert is not the successor")

	old, _ := store.GetDeployTarget(srv.db, tid)
	assert.Nil(t, old.LastStatus, "old target should not have been re-run")
}

func TestDeploy_RotationInheritsTargetsWithoutAutoDeploy(t *testing.T) {
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "manual.crt")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"name":      {"haproxy"},
		"cert_path": {certPath},
		"key_path":  {filepath.Join(dir, "manual.key")},
	})
	require.NoError(t, store.RecordDeployRun(srv.db, tid, store.DeployStatusOK, "deadbeef", "", time.Now().UTC()))

	newID := mustIssue(t, c, "/certs/"+leafID+"/rotate", url.Values{
		"subject_cn":      {"revoke.leaf.test"},
		"key_algo":        {"ecdsa"},
		"key_algo_params": {"P-256"},
		"san_dns":         {"revoke.leaf.test"},
		"validity_days":   {"90"},
	})

	newTargets, err := store.ListDeployTargets(srv.db, newID)
	require.NoError(t, err)
	require.Len(t, newTargets, 1)
	inherited := newTargets[0]
	assert.Equal(t, "haproxy", inherited.Name)
	assert.False(t, inherited.AutoOnRotate)

	newCert, err := store.GetCert(srv.db, newID)
	require.NoError(t, err)
	require.NotNil(t, inherited.LastDeployedSerial)
	assert.Equal(t, "deadbeef", *inherited.LastDeployedSerial, "prior run state not carried over")
	view := newDeployTargetView(inherited, newCert.SerialNumber)
	assert.Equal(t, "stale", view.EffectiveStatus)

	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "target without auto_on_rotate was deployed anyway")
}

func TestDeploy_AutoOnRotateRunsWhenTargetIsOnNewCert(t *testing.T) {
	// Direct test of the runAutoOnRotateTargets hook: seed a target on a
	// freshly-issued leaf, then call the hook with that cert. This isolates
	// the side-effect from the rotate handler's transactional boundary.
	srv, c, leafID, dir := deployFixture(t)
	certPath := filepath.Join(dir, "rot.crt")
	keyPath := filepath.Join(dir, "rot.key")
	tid := createTarget(t, c, srv, leafID, url.Values{
		"cert_path":      {certPath},
		"key_path":       {keyPath},
		"auto_on_rotate": {"1"},
	})

	cert, _ := store.GetCert(srv.db, leafID)
	srv.runAutoOnRotateTargets(httpRequestForCtx(), cert)

	got, _ := store.GetDeployTarget(srv.db, tid)
	require.NotNil(t, got.LastStatus, "auto-on-rotate did not run target")
	assert.Equal(t, "ok", *got.LastStatus, "auto-on-rotate target status")
	_, err := os.Stat(certPath)
	assert.NoError(t, err, "cert not written")
}

// httpRequestForCtx synthesises a request just so handlers that grab
// r.Context() have something to use. The runAutoOnRotateTargets hook only
// reads Done()/Err()/etc., never the body.
func httpRequestForCtx() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	return r
}
