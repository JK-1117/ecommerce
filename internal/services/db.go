package services

import "database/sql"

func GetNullString(str string) sql.NullString {
	nStr := sql.NullString{}
	if str != "" {
		nStr.String = str
		nStr.Valid = true
	}

	return nStr
}

func ParseNullString(nStr sql.NullString) string {
	var str string
	if nStr.Valid {
		str = nStr.String
	}

	return str
}
