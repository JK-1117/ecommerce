package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"time"

	"github.com/JK-1117/go-htmx-base/internal/database"
	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/JK-1117/go-htmx-base/internal/template/emails"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/sqlc-dev/pqtype"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
)

type Perm int

const (
	RESTRICTED Perm = iota
	OWNER_ONLY
	ALLOWED
)

const C_USERID = "UserId"
const C_ISADMIN = "IsAdministrator"
const C_USERROLES = "UserRoles"
const C_PERMISSION = "Permission"
const MIN_PASSWORD_ENTROPY = 60

type Permission struct {
	Create Perm `json:"create" redis:"create"`
	Read   Perm `json:"read" redis:"read"`
	Update Perm `json:"update" redis:"update"`
	Delete Perm `json:"delete" redis:"delete"`
	Print  Perm `json:"print" redis:"print"`
}

type Account struct {
	ID              uuid.UUID `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	Email           string    `json:"email"`
	ProfilePicture  string    `json:"profile_picture"`
	IsAdministrator bool      `json:"is_admin"`
	Active          bool      `json:"active"`
}

type LoginSession struct {
	SessionID string      `json:"session_id"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	UserID    uuid.UUID   `json:"user_id"`
	LastLogin time.Time   `json:"last_login"`
	IpAddr    pqtype.Inet `json:"ip_addr"`
	UserAgent string      `json:"user_agent,omitempty"`
	ExpiredAt time.Time   `json:"expired_at"`
}

type AuthService struct {
	db  *sql.DB
	q   *database.Queries
	rdb *redis.Client
}

func NewAuthService(db *sql.DB, q *database.Queries, rdb *redis.Client) *AuthService {
	return &AuthService{
		db:  db,
		q:   q,
		rdb: rdb,
	}
}

type SignUpParams struct {
	Password       string `json:"password"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	ProfilePicture string `json:"profile_picture"`
}

func (service *AuthService) SignUp(c echo.Context, params SignUpParams) (uuid.UUID, error) {
	logger, _ := logging.GetLogger()
	err := validateCreateAccount(params.Password, params.Email)
	if err != nil {
		return uuid.Nil, err
	}
	_, err = service.q.GetAccountByEmail(c.Request().Context(), params.Email)
	if err == nil {
		return uuid.Nil, ValidationError{fmt.Sprintf("User with email: %v already exists, please try login.", params.Email)}
	}

	tx, err := service.db.Begin()
	if err != nil {
		logger.App.Err(fmt.Sprintf("error Creating Account, error: %v, payload: %v", err, params))
		return uuid.Nil, err
	}
	defer tx.Rollback()
	qtx := service.q.WithTx(tx)

	passHash, err := bcrypt.GenerateFromPassword([]byte(params.Password), 10)
	if err != nil {
		return uuid.Nil, err
	}
	dbFirstName := GetNullString(params.FirstName)
	dbLastName := GetNullString(params.LastName)

	if params.ProfilePicture == "" {
		params.ProfilePicture = "/files/default_profile_pic.png"
	}
	dbProfilePicture := GetNullString(params.ProfilePicture)
	account, err := qtx.CreateAccount(c.Request().Context(), database.CreateAccountParams{
		ID:              uuid.New(),
		Password:        string(passHash),
		FirstName:       dbFirstName,
		LastName:        dbLastName,
		Email:           params.Email,
		ProfilePicture:  dbProfilePicture,
		IsAdministrator: false,
	})
	if err != nil {
		logger.App.Err(fmt.Sprintf("error Creating Account, error: %v, payload: %v", err, params))
		return uuid.Nil, err
	}

	_, err = qtx.CreateUserRole(c.Request().Context(), database.CreateUserRoleParams{
		UserID: account.ID,
		Role:   database.RoleEnumCLIENT,
	})
	if err != nil {
		logger.App.Err(fmt.Sprintf("error Creating User Role, error: %v, payload: %v", err, params))
		return uuid.Nil, err
	}

	if err = tx.Commit(); err != nil {
		logger.App.Err(fmt.Sprintf("error Commiting SignUp, error: %v, payload: %v", err, params))
		return uuid.Nil, err
	}

	go func() {
		m := GetMailService()
		err := m.SendMail(MailHeader{
			Subject: "Welcome to Our System!",
			To:      []string{account.Email},
		}, fmt.Sprintf("Dear %s, \n Welcome to Our System!&#127881; \n Your account is set up and ready to go. Start exploring our platform and make the most of it today. \n\n Best Regards,\n App Team", account.FirstName.String))
		if err != nil {
			logger.App.Err(fmt.Sprintf("error Sending Welcome Email, error: %v", err))
		}
	}()
	return account.ID, nil
}

func validateCreateAccount(password string, email string) error {
	if len(email) == 0 {
		return ValidationError{"Email is missing."}
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ValidationError{"Invalid Email Format: " + err.Error()}
	}

	if err = validatePassword(password); err != nil {
		return ValidationError{err.Error()}
	}
	return nil
}
func validatePassword(password string) error {
	if len(password) == 0 {
		return errors.New("Password is missing.")
	}
	if len(password) > 72 {
		return errors.New("Password is too long.")
	}
	return passwordvalidator.Validate(password, MIN_PASSWORD_ENTROPY)
}

type VerifyAccountParams struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (service *AuthService) VerifyAccount(c echo.Context, params VerifyAccountParams) (*Account, error) {
	logger, _ := logging.GetLogger()

	if params.Password == "" || params.Email == "" {
		return nil, ValidationError{"Incorrect email or password."}
	}
	account, err := service.q.GetAccountByEmail(c.Request().Context(), params.Email)
	if err != nil {
		logger.App.Err(fmt.Sprintf("error GetAccountByEmail in VerifyAccount, error: %v", err))
		return nil, err
	}
	if err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(params.Password)); err != nil {
		return nil, err
	}

	return parseAccount(account), nil
}

type GetResourcePermissionsParams struct {
	Resource string              `json:"resource"`
	Roles    []database.RoleEnum `json:"roles"`
}

func (service *AuthService) GetResourcePermissions(c echo.Context, params GetResourcePermissionsParams) (Permission, error) {
	logger, _ := logging.GetLogger()

	var result Permission
	for _, r := range params.Roles {
		key := "permission:" + string(r)
		cmd := service.rdb.HGet(c.Request().Context(), key, params.Resource)
		var perm Permission
		if err := cmd.Err(); err != nil {
			perm, err = service.cachePermission(c.Request().Context(), r, params.Resource)
			if err != nil {
				return result, err
			}
		} else {
			err = json.Unmarshal([]byte(cmd.Val()), &perm)
			if err != nil {
				logger.App.Err(fmt.Sprintf("parsed err: %v", err))
				return result, err
			}
			if err != nil {
				logger.App.Err(fmt.Sprintf("error Caching Permission, error: %v", err))
				return result, err
			}
			// stale-while-revalidate
			// Get from cache first for performance, then update cache for revalidate
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				service.cachePermission(ctx, r, params.Resource)
			}()
		}
		result = MergePermission(result, perm)
	}

	return result, nil
}

type ForgotPasswordParams struct {
	Email    string  `json:"email"`
	Redirect url.URL `json:"redirect"`
}

func (service *AuthService) ForgotPassword(c echo.Context, params ForgotPasswordParams) error {
	logger, _ := logging.GetLogger()

	/*
		https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html#introduction
		Ensure that responses return in a consistent amount of time to prevent an attacker enumerating
		which accounts exist. This could be achieved by using asynchronous calls or by making
		sure that the same logic is followed, instead of using a quick exit method.
	*/
	var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	sid := base32RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	userAgent := GetNullString(c.Request().UserAgent())
	ipAddr := pqtype.Inet{}
	ipAddr.Scan(c.RealIP())

	account, err := service.q.GetAccountByEmail(c.Request().Context(), params.Email)
	if err == sql.ErrNoRows {
		logger.App.Err(fmt.Sprintf("account not found with emal: %v in ForgotPassword: %v", params.Email, err))
		return nil
	} else if err != nil {
		logger.App.Err(fmt.Sprintf("error GetAccountByEmail in ForgotPassword: %v", err))
		return err
	}

	_, err = service.q.CreateResetSession(c.Request().Context(), database.CreateResetSessionParams{
		SessionID: sid,
		UserID:    account.ID,
		LastLogin: time.Now(),
		UserAgent: userAgent,
		ExpiredAt: time.Now().Add(5 * time.Minute),
		IpAddr:    ipAddr,
	})
	if err != nil {
		logger.App.Err(fmt.Sprintf("error CreateResetSession in ForgotPassword: %v", err))
		return err
	}

	// hash := md5.Sum([]byte(sid))
	// tokens := hex.EncodeToString(hash[:])
	q := params.Redirect.Query()
	// q.Set("token", tokens)
	q.Set("token", sid)
	params.Redirect.RawQuery = q.Encode()

	// send email tell them to reset in same browser
	ctx := context.Background()
	var html []byte
	buf := bytes.NewBuffer(html)
	emails.ForgotPassword(account.FirstName.String, params.Redirect.String()).Render(ctx, buf)

	go func() {
		m := GetMailService()
		err := m.SendMail(MailHeader{
			Subject: "Online Printing System - Reset Password",
			To:      []string{account.Email},
		}, buf.String())
		if err != nil {
			logger.App.Err(fmt.Sprintf("error Sending Reset Password Email, error: %v", err))
		}
	}()

	return nil
}

type ResetPasswordParams struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (service *AuthService) ResetPassword(c echo.Context, params ResetPasswordParams) error {
	logger, _ := logging.GetLogger()

	if err := validatePassword(params.Password); err != nil {
		return ValidationError{err.Error()}
	}

	userAgent := GetNullString(c.Request().UserAgent())
	ipAddr := pqtype.Inet{}
	ipAddr.Scan(c.RealIP())
	resetSession, err := service.q.GetResetSession(c.Request().Context(), database.GetResetSessionParams{
		SessionID: params.Token,
		UserAgent: userAgent,
		IpAddr:    ipAddr,
	})
	if err != nil {
		logger.App.Err(fmt.Sprintf("error GetResetSession in ResetPassword: %v", err))
		return UnauthorizedError{}
	}

	if resetSession.ExpiredAt.Before(time.Now()) {
		return UnauthorizedError{}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(params.Password), 10)
	if err != nil {
		return err
	}
	account, err := service.q.UpdateAccountPassword(c.Request().Context(), database.UpdateAccountPasswordParams{
		Password: string(hash),
		ID:       resetSession.UserID,
	})
	if err != nil {
		return err
	}

	// Alert user that the password has been reset
	go func() {
		ctx := context.Background()
		var html []byte
		buf := bytes.NewBuffer(html)
		emails.PasswordReset(account.FirstName.String).Render(ctx, buf)

		m := GetMailService()
		err := m.SendMail(MailHeader{
			Subject: "Online Printing System - Password Reset",
			To:      []string{account.Email},
		}, buf.String())
		if err != nil {
			logger.App.Err(fmt.Sprintf("error Sending Password Reset Email, error: %v", err))
		}
	}()

	return nil
}

func (service *AuthService) cachePermission(c context.Context, role database.RoleEnum, resource string) (Permission, error) {
	logger, _ := logging.GetLogger()
	perm, err := service.q.GetResourcePermissionByRole(c, database.GetResourcePermissionByRoleParams{
		Resource: resource,
		Role:     role,
	})
	if err != nil {
		logger.App.Err(fmt.Sprintf("error GetResourcePermissionByRole, error: %v", err))
		return Permission{}, err
	}

	key := "permission:" + string(perm.Role)
	err = service.rdb.HSet(c, key, resource, perm.Permissions).Err()
	if err != nil {
		logger.App.Err(fmt.Sprintf("error Caching Permission, error: %v", err))
	}

	var cachedPerm Permission
	err = json.Unmarshal([]byte(perm.Permissions.(string)), &cachedPerm)
	if err != nil {
		logger.App.Err(fmt.Sprintf("error Unmarshal Permission, error: %v", err))
	}
	return cachedPerm, nil
}

func MergePermission(a Permission, b Permission) Permission {
	var result Permission
	result.Create = MergePermLevel(a.Create, b.Create)
	result.Read = MergePermLevel(a.Read, b.Read)
	result.Update = MergePermLevel(a.Update, b.Update)
	result.Delete = MergePermLevel(a.Delete, b.Delete)
	result.Print = MergePermLevel(a.Print, b.Print)

	return result
}

func MergePermLevel(a Perm, b Perm) Perm {
	if a > b {
		return a
	}
	return b
}

func parseLoginSession(dbLoginSession database.LoginSession) *LoginSession {
	userAgent := ParseNullString(dbLoginSession.UserAgent)

	return &LoginSession{
		SessionID: dbLoginSession.SessionID,
		CreatedAt: dbLoginSession.CreatedAt,
		UpdatedAt: dbLoginSession.UpdatedAt,
		UserID:    dbLoginSession.UserID,
		LastLogin: dbLoginSession.LastLogin,
		IpAddr:    dbLoginSession.IpAddr,
		UserAgent: userAgent,
		ExpiredAt: dbLoginSession.ExpiredAt,
	}
}

func parseAccount(dbAccount database.Account) *Account {
	firstName := ParseNullString(dbAccount.FirstName)
	lastName := ParseNullString(dbAccount.LastName)
	profilePicture := ParseNullString(dbAccount.ProfilePicture)

	return &Account{
		ID:              dbAccount.ID,
		CreatedAt:       dbAccount.CreatedAt,
		UpdatedAt:       dbAccount.UpdatedAt,
		FirstName:       firstName,
		LastName:        lastName,
		Email:           dbAccount.Email,
		ProfilePicture:  profilePicture,
		IsAdministrator: dbAccount.IsAdministrator,
		Active:          dbAccount.Active,
	}
}
