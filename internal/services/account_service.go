package services

import (
	"database/sql"
	"mime/multipart"

	"github.com/JK-1117/go-htmx-base/internal/database"
	logging "github.com/JK-1117/go-htmx-base/internal/logger"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AccountService struct {
	db *sql.DB
	q  *database.Queries
}

func NewAccountService(db *sql.DB, q *database.Queries) *AccountService {
	return &AccountService{
		db: db,
		q:  q,
	}
}

func (service *AccountService) GetAccount(c echo.Context, userId string) (*Account, error) {
	logger, _ := logging.GetLogger()
	perm := c.Get(C_PERMISSION).(Permission)
	uid, err := uuid.Parse(userId)
	if err != nil {
		logger.App.Err(err.Error())
		return nil, UnauthorizedError{err.Error()}
	}

	if perm.Read == OWNER_ONLY && uid != c.Get(C_USERID) {
		return nil, UnauthorizedError{}
	}

	account, err := service.q.GetActiveAccountById(c.Request().Context(), uid)
	if err != nil {
		logger.App.Err(err.Error())
		return nil, err
	}

	return parseAccount(account), nil
}

type UpdateAccountParams struct {
	UserID    uuid.UUID
	FirstName string
	LastName  string
	File      *multipart.FileHeader
}

func (service *AccountService) UpdateAccount(c echo.Context, params UpdateAccountParams) (*Account, error) {
	logger, _ := logging.GetLogger()
	perm := c.Get(C_PERMISSION).(Permission)
	if perm.Update == RESTRICTED {
		return nil, UnauthorizedError{}
	}

	dbParams := database.UpdateAccountParams{
		ID:        params.UserID,
		FirstName: GetNullString(params.FirstName),
		LastName:  GetNullString(params.LastName),
	}

	if params.File != nil {
		fileurl, err := SaveFile(params.File)
		if err != nil {
			logger.App.Err(err.Error())
			return nil, err
		}
		dbParams.ProfilePicture = GetNullString(fileurl)
	}

	account, err := service.q.UpdateAccount(c.Request().Context(), dbParams)
	if err != nil {
		logger.App.Err(err.Error())
		return nil, err
	}

	return parseAccount(account), nil
}
