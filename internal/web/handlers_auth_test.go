package web

import (
	"database/sql"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/Klice/homepki/internal/config"
	"github.com/Klice/homepki/internal/crypto"
	"github.com/Klice/homepki/internal/store"
)

// testServer returns a Server backed by a fresh on-disk SQLite (with the v1
// schema applied) and an empty keystore. Tests drive it through ServeHTTP
// using a *clientLite to thread cookies between requests like a browser.
func testServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	db, err := store.Open(t.TempDir())
	require.NoError(t, err, "store.Open")
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, store.Migrate(db), "Migrate")
	srv, err := New(config.Config{CRLBaseURL: "https://test.lan"}, db, crypto.NewKeystore())
	require.NoError(t, err, "New")
	return srv, db
}

// csrfFormFieldRE pulls the masked CSRF token value out of a rendered
// form. gorilla/csrf rotates the masked value per render, so the test
// client extracts it from each response body and uses it on the next POST.
var csrfFormFieldRE = regexp.MustCompile(`name="` + csrfFormField + `"\s+value="([^"]+)"`)

// clientLite holds cookies and the most-recently-rendered CSRF token
// between calls so a sequence of requests behaves like a single browser
// session.
type clientLite struct {
	t       *testing.T
	srv     http.Handler
	cookies map[string]*http.Cookie
	csrfTok string // most recent token extracted from a rendered form
}

func newClient(t *testing.T, srv http.Handler) *clientLite {
	return &clientLite{t: t, srv: srv, cookies: map[string]*http.Cookie{}}
}

func (c *clientLite) do(req *http.Request) *httptest.ResponseRecorder {
	c.t.Helper()
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	// gorilla/csrf treats unmarked requests as HTTPS by default and rejects
	// state-changing requests with no Referer. Set a same-origin Referer so
	// the test client looks like a normal browser navigating from the same
	// app.
	if req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", "https://example.com/")
	}
	w := httptest.NewRecorder()
	c.srv.ServeHTTP(w, req)
	for _, ck := range w.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	if m := csrfFormFieldRE.FindStringSubmatch(w.Body.String()); m != nil {
		// html/template escapes "+" -> "&#43;" inside attribute values; a
		// browser would HTML-decode before submitting, so we do the same.
		c.csrfTok = html.UnescapeString(m[1])
	}
	return w
}

func (c *clientLite) get(target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return c.do(req)
}

func (c *clientLite) postForm(target string, form url.Values) *httptest.ResponseRecorder {
	form.Set(csrfFormField, c.csrfTok)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req)
}

// validPassphrase is just long enough for MinPassphraseLen.
const validPassphrase = "correct horse battery"

// fastSetup primes the auth state much faster than going through the real
// handler — Argon2id at default params is too slow for unit tests. It writes
// salt+params+verifier into settings and installs a KEK derived with low
// Argon2id params, mirroring what handleSetupPost would have written.
func fastSetup(t *testing.T, srv *Server, db *sql.DB) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	params := crypto.KDFParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32}
	paramsJSON := []byte(`{"time":1,"memory":64,"threads":1,"key_len":32}`)
	kek, err := crypto.DeriveKEK([]byte(validPassphrase), salt, params)
	require.NoError(t, err)
	require.NoError(t, store.SetSetting(db, store.SettingKDFSalt, salt))
	require.NoError(t, store.SetSetting(db, store.SettingKDFParams, paramsJSON))
	require.NoError(t, store.SetSetting(db, store.SettingPassphraseVerifier, crypto.Verifier(kek)))
	require.NoError(t, srv.keystore.Install(kek))
}

// ---------------- index dispatcher ----------------

func TestIndex_RedirectsToSetupWhenNotSetUp(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)

	w := c.get("/")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/setup", w.Header().Get("Location"))
}

func TestIndex_RedirectsToUnlockWhenSetUpButLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

func TestIndex_RendersWhenUnlockedWithSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	// Establish a session by setting the cookie ourselves (simulating a
	// successful unlock).
	secret, err := srv.keystore.DeriveSessionSecret()
	require.NoError(t, err)
	value, err := SignSession(secret)
	require.NoError(t, err)
	c.cookies[SessionCookieName] = &http.Cookie{Name: SessionCookieName, Value: value}

	w := c.get("/")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "unlocked")
}

func TestIndex_OnlyExactRoot(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	w := c.get("/no-such-path")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------- setup ----------------

func TestSetupGet_RendersForm(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	w := c.get("/setup")
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `name="passphrase"`)
	assert.Contains(t, body, `name="csrf_token"`)
}

func TestSetupGet_RedirectsToUnlockWhenAlreadySetUp(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	c := newClient(t, srv)
	w := c.get("/setup")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
}

func TestSetupPost_RejectsShortPassphrase(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	c.get("/setup") // prime CSRF cookie

	w := c.postForm("/setup", url.Values{"passphrase": {"short"}, "passphrase2": {"short"}})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "at least 12 characters")
}

func TestSetupPost_RejectsMismatch(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	c.get("/setup")

	w := c.postForm("/setup", url.Values{
		"passphrase":  {"correct horse battery"},
		"passphrase2": {"correct horse battery!"},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "do not match")
}

// ---------------- unlock ----------------

func TestUnlockGet_RedirectsToSetupWhenNotSetUp(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	w := c.get("/unlock")
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/setup", w.Header().Get("Location"))
}

func TestUnlockGet_RendersFormWhenSetUpAndLocked(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	w := c.get("/unlock")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `name="passphrase"`)
}

func TestUnlockPost_WrongPassphrase(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie
	w := c.postForm("/unlock", url.Values{"passphrase": {"definitely-wrong"}})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "密码错误")
	assert.False(t, srv.keystore.IsUnlocked(), "keystore should remain locked after wrong passphrase")
}

func TestUnlockPost_CorrectPassphraseInstallsKEKAndSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()

	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie
	w := c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
	assert.True(t, srv.keystore.IsUnlocked(), "keystore should be unlocked after correct passphrase")
	assert.NotNil(t, c.cookies[SessionCookieName], "session cookie not issued")
}

// ---------------- lock ----------------

func TestLock_ZeroesKEKAndClearsSession(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)

	c := newClient(t, srv)
	c.get("/unlock")
	w := c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})
	require.Equal(t, http.StatusSeeOther, w.Code, "unlock failed")
	require.NotNil(t, c.cookies[SessionCookieName], "session cookie missing after unlock")

	w = c.postForm("/lock", url.Values{})
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/unlock", w.Header().Get("Location"))
	assert.False(t, srv.keystore.IsUnlocked(), "keystore should be locked")
	assert.Nil(t, c.cookies[SessionCookieName], "session cookie should be cleared")
}

func TestLock_IsIdempotent(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)
	// GET something that renders a form so the client picks up a CSRF
	// token. /unlock would 303 to /setup here (DB not yet initialized);
	// /setup renders the first-run form which carries the token.
	c.get("/setup")
	w := c.postForm("/lock", url.Values{})
	assert.Equal(t, http.StatusSeeOther, w.Code, "first lock")
	w = c.postForm("/lock", url.Values{})
	assert.Equal(t, http.StatusSeeOther, w.Code, "second lock")
}

// ---------------- end-to-end ----------------

func TestEndToEnd_SetupUnlockLockUnlock(t *testing.T) {
	srv, _ := testServer(t)
	c := newClient(t, srv)

	// 1. Visit /; redirected to /setup
	w := c.get("/")
	require.Equal(t, "/setup", w.Header().Get("Location"), "expected redirect to /setup")

	// 2. GET /setup primes CSRF; POST /setup writes verifier and installs KEK
	c.get("/setup")
	w = c.postForm("/setup", url.Values{
		"passphrase":  {validPassphrase},
		"passphrase2": {validPassphrase},
	})
	require.Equal(t, http.StatusSeeOther, w.Code, "setup failed")
	require.Equal(t, "/", w.Header().Get("Location"), "setup failed")

	// 3. /lock zeroes KEK and clears session
	w = c.postForm("/lock", url.Values{})
	require.Equal(t, http.StatusSeeOther, w.Code, "lock failed")

	// 4. GET / now redirects to /unlock
	w = c.get("/")
	require.Equal(t, "/unlock", w.Header().Get("Location"), "expected redirect to /unlock")

	// 5. Re-unlock; back at /
	c.get("/unlock")
	w = c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})
	require.Equal(t, http.StatusSeeOther, w.Code, "unlock failed")
	w = c.get("/")
	require.Equal(t, http.StatusOK, w.Code, "expected 200 at /")
	assert.Contains(t, w.Body.String(), "unlocked")
}
