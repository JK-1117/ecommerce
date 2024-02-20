package router

import (
	"database/sql"
	"net/http"

	"github.com/JK-1117/go-htmx-base/internal/database"
	"github.com/JK-1117/go-htmx-base/internal/services"
	"github.com/JK-1117/go-htmx-base/internal/template/components"
	"github.com/JK-1117/go-htmx-base/internal/template/pages"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AccountRouter struct {
	s *services.AccountService
}

func NewAccountRouter(db *sql.DB, q *database.Queries) *AccountRouter {
	s := services.NewAccountService(db, q)

	return &AccountRouter{s: s}
}

func (r *AccountRouter) RegisterRoute(e *echo.Group, auth AuthorizationMiddleware) {
	e.Use(auth("account"))
	e.GET("/me", r.MeView)
	e.GET("/me-form", r.MeFormView)

	account := e.Group("/api/v1/account")
	account.PUT("/me", r.UpdateMe)
}

func (r *AccountRouter) MeView(c echo.Context) error {
	userId := c.Get(services.C_USERID).(uuid.UUID)
	account, err := r.s.GetAccount(c, userId.String())
	if err != nil {
		switch v := err.(type) {
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, ErrGeneralMsg)
		case services.UnauthorizedError:
			return echo.NewHTTPError(http.StatusUnauthorized, v.Error())
		case services.ValidationError:
			return echo.NewHTTPError(http.StatusBadRequest, v.Error())
		}
	}

	return pages.MePage(account).Render(c.Request().Context(), c.Response().Writer)
}

func (r *AccountRouter) MeFormView(c echo.Context) error {
	userId := c.Get(services.C_USERID).(uuid.UUID)
	account, err := r.s.GetAccount(c, userId.String())
	if err != nil {
		switch v := err.(type) {
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, ErrGeneralMsg)
		case services.UnauthorizedError:
			return echo.NewHTTPError(http.StatusUnauthorized, v.Error())
		case services.ValidationError:
			return echo.NewHTTPError(http.StatusBadRequest, v.Error())
		}
	}

	return pages.MeForm(account).Render(c.Request().Context(), c.Response().Writer)
}

func (r *AccountRouter) UpdateMe(c echo.Context) error {
	userId, ok := c.Get(services.C_USERID).(uuid.UUID)
	if !ok {
		return components.FormMessage(components.FormMessageParams{
			ClassName: "bg-red-50 text-red-800 mb-8",
			Message:   ErrGeneralMsg,
			Attrs: map[string]any{
				"id": "message",
			},
		}).Render(c.Request().Context(), c.Response().Writer)
	}

	fName := c.FormValue("first_name")
	lName := c.FormValue("last_name")
	file, err := c.FormFile("profile_picture")
	_, err = r.s.UpdateAccount(c, services.UpdateAccountParams{
		UserID:    userId,
		FirstName: fName,
		LastName:  lName,
		File:      file,
	})
	if err != nil {
		errMsg := ErrGeneralMsg
		switch v := err.(type) {
		default:
			errMsg = ErrGeneralMsg
		case services.UnauthorizedError:
			errMsg = v.Error()
		}
		return components.FormMessage(components.FormMessageParams{
			ClassName: "bg-red-50 text-red-800 mb-8",
			Message:   errMsg,
			Attrs: map[string]any{
				"id": "message",
			},
		}).Render(c.Request().Context(), c.Response().Writer)
	}

	c.Response().Header().Add("HX-Location", "/me")
	return c.NoContent(http.StatusNoContent)
}
