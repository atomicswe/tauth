package examples

import "github.com/atomicswe/tauth"

func ValidateToken(user string) (string, string, error) {
	issued, err := IssueTokens(user)
	if err != nil {
		return "", "", err
	}

	return tauth.ValidateToken(issued.AccessToken.Token)
}
