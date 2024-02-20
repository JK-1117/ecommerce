package services

type UnauthorizedError struct {
	s string
}

func (e UnauthorizedError) Error() string {
	if e.s == "" {
		return "You are not authorized to access this resource."
	}
	return e.s
}

type ValidationError struct {
	s string
}

func (e ValidationError) Error() string {
	return e.s
}

type GeneralError struct {
	s string
}

func (e GeneralError) Error() string {
	if e.s == "" {
		return "Something went wrong, try again later."
	}
	return e.s
}
