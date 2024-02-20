package router

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/JK-1117/go-htmx-base/internal/database"
	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/JK-1117/go-htmx-base/internal/services"
	"github.com/JK-1117/go-htmx-base/internal/template/components"
	"github.com/JK-1117/go-htmx-base/internal/template/pages"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

type AuthRouter struct {
	s            *services.AuthService
	SessionStore *SessionStore
}

func NewAuthRouter(db *sql.DB, q *database.Queries, rdb *redis.Client) *AuthRouter {
	s := services.NewAuthService(db, q, rdb)
	store := NewSessionStore(q, rdb)

	return &AuthRouter{
		s:            s,
		SessionStore: store,
	}
}

func (r *AuthRouter) RegisterRoute(e *echo.Echo) {
	e.GET("/signup", r.SignUpView)
	e.GET("/login", r.LoginView)
	e.GET("/forgot-password", r.ForgotPasswordView)

	api := e.Group("/api/v1")
	api.POST("/signup", r.SignUp)
	api.POST("/login", r.LogIn)
	api.POST("/forgot-password", r.ForgotPassword)
	api.POST("/logout", r.LogOut)
}

func (r *AuthRouter) SignUpView(c echo.Context) error {
	return pages.SignUpPage().Render(c.Request().Context(), c.Response().Writer)
}
func (r *AuthRouter) SignUp(c echo.Context) error {
	logger, _ := logging.GetLogger()

	params := services.SignUpParams{
		Email:    c.FormValue("email"),
		Password: c.FormValue("password"),
	}

	user_id, err := r.s.SignUp(c, params)
	if err != nil {
		switch v := err.(type) {
		default:
			return components.FormMessage(components.FormMessageParams{
				ClassName: "bg-red-50 text-red-800",
				Message:   ErrGeneralMsg,
			}).Render(c.Request().Context(), c.Response().Writer)
		case services.ValidationError:
			return components.FormMessage(components.FormMessageParams{
				ClassName: "bg-red-50 text-red-800",
				Message:   v.Error(),
			}).Render(c.Request().Context(), c.Response().Writer)
		}
	}

	successMsg := components.FormMessage(components.FormMessageParams{
		ClassName: "bg-teal-50 text-teal-800",
		Message:   "Signup Successfully, you may proceed to login.",
	})
	redirectLink := "/"
	if c.FormValue("redirect") != "" {
		redirectLink = c.FormValue("redirect")
	}
	session, err := r.SessionStore.NewSession(c, user_id)
	err = r.SessionStore.SetSessionCookie(c, session)
	if err != nil {
		// User created, but session cannot be created
		logger.App.Err(err.Error())
		redirectLink = fmt.Sprintf("/login?redirect=%s", redirectLink)
		c.Response().Header().Add("HX-Replace-Url", redirectLink)

		successMsg.Render(c.Request().Context(), c.Response().Writer)
		return pages.DelayRedirectTo(redirectLink).Render(c.Request().Context(), c.Response().Writer)
	}

	c.Response().Header().Add("HX-Replace-Url", redirectLink)
	successMsg.Render(c.Request().Context(), c.Response().Writer)
	return pages.DelayRedirectTo(redirectLink).Render(c.Request().Context(), c.Response().Writer)
}

func (r *AuthRouter) LoginView(c echo.Context) error {
	return pages.LoginPage().Render(c.Request().Context(), c.Response().Writer)
}
func (r *AuthRouter) LogIn(c echo.Context) error {
	logger, _ := logging.GetLogger()

	params := services.VerifyAccountParams{
		Email:    c.FormValue("email"),
		Password: c.FormValue("password"),
	}

	account, err := r.s.VerifyAccount(c, params)
	if err != nil {
		return components.FormMessage(components.FormMessageParams{
			ClassName: "bg-red-50 text-red-800",
			Message:   "Incorrect email or password.",
		}).Render(c.Request().Context(), c.Response().Writer)
	}
	session, err := r.SessionStore.NewSession(c, account.ID)
	err = r.SessionStore.SetSessionCookie(c, session)
	if err != nil {
		logger.App.Err(err.Error())
		return components.FormMessage(components.FormMessageParams{
			ClassName: "bg-red-50 text-red-800",
			Message:   ErrGeneralMsg,
		}).Render(c.Request().Context(), c.Response().Writer)
	}

	redirectLink := "/"
	if c.FormValue("redirect") != "" {
		redirectLink = c.FormValue("redirect")
	}
	c.Response().Header().Add("HX-Replace-Url", redirectLink)
	components.FormMessage(components.FormMessageParams{
		ClassName: "bg-teal-50 text-teal-800",
		Message:   "Login Successfully, you will be redirected shortly.",
	}).Render(c.Request().Context(), c.Response().Writer)
	return pages.DelayRedirectTo(redirectLink).Render(c.Request().Context(), c.Response().Writer)
}

func (r *AuthRouter) LogOut(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     SESSIONCOOKIE,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
		Value:    "",
	})
	c.Response().Header().Add("HX-Location", "/login")

	return c.NoContent(http.StatusOK)
}

func (r *AuthRouter) ForgotPasswordView(c echo.Context) error {
	return pages.ForgotPasswordPage().Render(c.Request().Context(), c.Response().Writer)
}
func (r *AuthRouter) ForgotPassword(c echo.Context) error {
	redirect := url.URL{
		Scheme: os.Getenv("SCHEME"),
		Host:   os.Getenv("HOST"),
		Path:   "reset-password",
	}
	params := services.ForgotPasswordParams{
		Email:    c.Request().FormValue("email"),
		Redirect: redirect,
	}

	if err := r.s.ForgotPassword(c, params); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, ErrGeneralMsg)
	}

	c.Response().Header().Add("HX-Retarget", "#authForm")
	c.Response().Header().Add("HX-Reswap", "innerHTML")

	return c.String(http.StatusOK, "<p class='text-center text-gray-900 font-semibold'>An email with instructions to reset your password will be sent to your email if an account is registered under it. Remember to check the junk mailbox.</p>")
}

func (r *AuthRouter) ResetPasswordView(c echo.Context) error {
	c.Response().Header().Add("Referrer-Policy", "no-referrer")
	return nil
}

type AuthorizationMiddleware func(string) echo.MiddlewareFunc

func (r *AuthRouter) Authorization(resource string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if resource == "" {
				return echo.NewHTTPError(http.StatusInternalServerError, "Resource missing for authorization.")
			}

			perm, err := r.s.GetResourcePermissions(c, services.GetResourcePermissionsParams{
				Resource: resource,
				Roles:    c.Get(services.C_USERROLES).([]database.RoleEnum),
			})
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, ErrGeneralMsg)
			}

			if perm.Read == services.RESTRICTED {
				return echo.NewHTTPError(http.StatusForbidden, "You are not authorized to access this resource.")
			}
			c.Set(services.C_PERMISSION, perm)
			return next(c)
		}
	}
}
