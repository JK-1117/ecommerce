package services

import "regexp"

func validatePhoneNumber(pn string) bool {
	match, _ := regexp.Match(`^\+60(?:1[0-46-9]\d{7,8}|[3-79]\d{6,8}|8[0-9]{6,8})$`, []byte(pn))

	return match
}

func validatePostalCode(pc string) bool {
	match, _ := regexp.Match(`^\d{5}$`, []byte(pc))

	return match
}
