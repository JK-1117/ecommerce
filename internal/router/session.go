package router

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/JK-1117/go-htmx-base/internal/database"
	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/JK-1117/go-htmx-base/internal/services"
	"github.com/JK-1117/go-htmx-base/internal/template/pages"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sqlc-dev/pqtype"
)

type SessionStore struct {
	q       *database.Queries
	rdb     *redis.Client
	encoder *securecookie.SecureCookie
}
type Session struct {
	SessionID string `json:"session_id" redis:"session_id"`
	UserID    string `json:"user_id" redis:"user_id"`
	IpAddr    string `json:"ip_addr" redis:"ip_addr"`
	UserAgent string `json:"user_agent,omitempty" redis:"user_agent"`
	ExpiredAt int64  `json:"expired_at" redis:"expired_at"`
}

const SESSIONCOOKIE = "X-APP-SID"
const SESSION_DURATION = 4 * time.Hour
const TIMEOUT = 2 * time.Second

func NewSessionStore(q *database.Queries, rdb *redis.Client) *SessionStore {
	var COOKIE_HASHKEY string = os.Getenv("COOKIE_HASHKEY")
	var COOKIE_BLOCKKEY string = os.Getenv("COOKIE_BLOCKKEY")

	return &SessionStore{
		q:       q,
		rdb:     rdb,
		encoder: securecookie.New([]byte(COOKIE_HASHKEY), []byte(COOKIE_BLOCKKEY)),
	}
}

func (store *SessionStore) Get(c echo.Context) (*Session, error) {
	sessionCookie, err := c.Cookie(SESSIONCOOKIE)
	if err != nil {
		return nil, err
	}
	var sessionId string
	err = store.encoder.Decode(SESSIONCOOKIE, sessionCookie.Value, &sessionId)
	if err != nil {
		return nil, err
	}

	redisKey := "session:" + sessionId
	res := store.rdb.HGetAll(c.Request().Context(), redisKey)
	if err := res.Err(); err != nil {
		return nil, err
	}
	if len(res.Val()) > 0 {
		var session Session
		err = res.Scan(&session)
		if err != nil {
			return nil, err
		}

		err = session.validate(c)
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
			defer cancel()
			store.rdb.Del(ctx, redisKey)
			return nil, err
		}
		return &session, nil
	}

	// Search for database if not found in redis
	loginSession, err := store.q.GetSessionBySessionId(c.Request().Context(), sessionId)
	if err != nil {
		return nil, err
	}
	session := parseDbSession(&loginSession)
	err = session.validate(c)
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
		defer cancel()
		store.q.DeleteSessionBySessionId(ctx, sessionId)
		return nil, err
	}
	return store.Cache(c.Request().Context(), session)
}

func (store *SessionStore) NewSession(c echo.Context, userId uuid.UUID) (*Session, error) {
	var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	sid := base32RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	userAgent := services.GetNullString(c.Request().UserAgent())
	ipAddr := pqtype.Inet{}
	ipAddr.Scan(c.RealIP())
	loginSession, err := store.q.CreateLoginSession(c.Request().Context(), database.CreateLoginSessionParams{
		SessionID: sid,
		UserID:    userId,
		LastLogin: time.Now(),
		UserAgent: userAgent,
		ExpiredAt: time.Now().Add(SESSION_DURATION),
		IpAddr:    ipAddr,
	})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error Creating Session, error: %v", err))
	}

	session := parseDbSession(&loginSession)

	return store.Cache(c.Request().Context(), session)
}

func (store *SessionStore) Cache(c context.Context, session *Session) (*Session, error) {
	err := store.rdb.HSet(c, "session:"+session.SessionID, session).Err()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("error Creating Session, error: %v", err))
	}
	return session, nil
}

func (store *SessionStore) SetSessionCookie(c echo.Context, session *Session) error {
	if session == nil {
		return errors.New("Session not provided.")
	}
	encoded, err := store.encoder.Encode(SESSIONCOOKIE, session.SessionID)
	if err != nil {
		return err
	}
	expiredAt := time.Unix(session.ExpiredAt, 0)
	cookie := &http.Cookie{
		Name:     SESSIONCOOKIE,
		Value:    encoded,
		Domain:   os.Getenv("DOMAIN"),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(time.Now().Sub(expiredAt).Abs().Seconds()),
		Path:     "/",
	}
	c.SetCookie(cookie)
	return nil
}

func showUnauthorizeMessage(c echo.Context) error {
	link := fmt.Sprintf("/login?redirect=%s", c.Request().URL.String())

	if c.Request().Header.Get("HX-Request") == "true" && c.Request().Header.Get("HX-Boosted") != "" {
		c.Response().Header().Add("HX-Redirect", link)
		return echo.NewHTTPError(http.StatusUnauthorized, errors.New("Session expired, try login again."))
	}
	return pages.MessagePage(pages.MessagePageParams{
		StatusCode: http.StatusUnauthorized,
		Title:      "Session Expired",
		Message:    "Your session has expired. Please log in again.",
		Link:       link,
		LinkLabel:  "Go to Login",
		HideShell:  true,
	}).Render(c.Request().Context(), c.Response().Writer)
}
func (store *SessionStore) SessionAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger, _ := logging.GetLogger()

		session, err := store.Get(c)
		if err != nil {
			logger.App.Err(err.Error())
			return showUnauthorizeMessage(c)
		}

		userId, err := uuid.Parse(session.UserID)
		if err != nil {
			logger.App.Err(err.Error())
			return showUnauthorizeMessage(c)
		}
		account, err := store.q.GetActiveAccountById(c.Request().Context(), userId)
		if err != nil {
			logger.App.Err(err.Error())
			return showUnauthorizeMessage(c)
		}
		roles, err := store.q.GetUserRoleByUser(c.Request().Context(), userId)
		if err != nil {
			logger.App.Err(err.Error())
			return showUnauthorizeMessage(c)
		}
		var userRoles []database.RoleEnum
		for _, r := range roles {
			userRoles = append(userRoles, database.RoleEnum(r.Role))
		}

		c.Set(services.C_USERID, account.ID)
		c.Set(services.C_ISADMIN, account.IsAdministrator)
		c.Set(services.C_USERROLES, userRoles)
		return next(c)
	}
}

func (session *Session) validate(c echo.Context) error {
	ipAddr := pqtype.Inet{}
	ipAddr.Scan(c.RealIP())

	if session.IpAddr != ipAddr.IPNet.String() {
		return errors.New("Ip address does not match.")
	}

	if session.UserAgent != c.Request().UserAgent() {
		return errors.New("User agent does not match.")
	}

	expiredAt := time.Unix(session.ExpiredAt, 0)
	if expiredAt.Before(time.Now()) {
		return errors.New("Session expired, please login again.")
	}

	return nil
}

func parseDbSession(loginSession *database.LoginSession) *Session {
	userAgent := services.ParseNullString(loginSession.UserAgent)
	return &Session{
		SessionID: loginSession.SessionID,
		UserID:    loginSession.UserID.String(),
		IpAddr:    loginSession.IpAddr.IPNet.String(),
		UserAgent: userAgent,
		ExpiredAt: loginSession.ExpiredAt.Unix(),
	}
}
