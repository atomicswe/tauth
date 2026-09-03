# tauth

`tauth` issues HS256 JWT access tokens and opaque refresh tokens. With the refresh token you can recreate the access token and keep a session alive (`tauth` does not maintain sessions, only keeps tokens stored in memory, for now)

```bash
go get github.com/atomicswe/tauth
```

Requires Go 1.22 or later.

## Disclaimer

This package was made with my specific needs in mind, so it likely won't have all the features someone needs. If that's the case, follow the [contributing](#contributing) section to know more.

## Known limitations

`tauth` is a very simple and to the point package, with that in mind, one of the decisions made during the development was to not integrate a database with it. This means that the only store that `tauth` provides is in-memory, meaning it lives as long as the application using it lives. This is also an issue if you are, for example, deploying 2 pods of a service that uses this package, as the storage will divert. In the future I will likely add the option to integrate with a database, fixing these issues.

## Configuration

| Env variable       | Required | Description                                         |
| ------------------ | -------- | --------------------------------------------------- |
| `TAUTH_SECRET_KEY` | yes      | HMAC secret used to sign and validate access tokens |
| `TAUTH_ISS`        | no       | JWT issuer. Defaults to `tauth-default-iss`         |

## Usage

### Issue tokens

All options are optional. Access tokens default to 5 minutes, refresh tokens to 24 hours. Access tokens must be at least 5 minutes. Refresh tokens must be at least 1 hour.

```go
package main

import (
	"fmt"
	"time"

	"github.com/atomicswe/tauth"
)

func main() {
	atExp := 15 * time.Minute
	rtExp := 48 * time.Hour

	tokens, err := tauth.IssueTokens("alice", tauth.TAuthOptions{
		ATExpiration: &atExp,
		RTExpiration: &rtExp,
		CustomClaims: `{"role":"admin"}`,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(tokens.AccessToken.Token)
	fmt.Println(tokens.RefreshToken.Token)
}
```

`user` is stored in the JWT `user` claim and used as the in-memory session key. Issuing again for the same user replaces the previously stored tokens.

### Validate an access token

```go
user, customClaims, err := tauth.ValidateToken(tokens.AccessToken.Token)
if err != nil {
	panic(err)
}

fmt.Println(user, customClaims)
```

Validation checks the signature, issuer, and expiry. It does not look up the in-memory session.

### Refresh tokens

```go
refreshed, err := tauth.RefreshTokens("alice", tokens.RefreshToken.Token)
if err != nil {
	panic(err)
}
```

The new pair reuses the previous lifetimes and custom claims, and replaces the stored session for that user.

## Errors

Sentinel errors live in [`pkg/terrors`](https://pkg.go.dev/github.com/atomicswe/tauth/pkg/terrors):

```go
import (
	"errors"

	"github.com/atomicswe/tauth/pkg/terrors"
)

if errors.Is(err, terrors.TErrSecretKeyMissing) {
	// TAUTH_SECRET_KEY is not set
}
```

## In-memory sessions

Refresh tokens are stored in process memory. `RefreshTokens` only works in the same process that called `IssueTokens`.

## Contributing

Issues and pull requests are welcome.

Branch from `main`, add tests for new behavior, and run the test suite:

```bash
make test
```

Then open a pull request against `main`. If you do not have write access, GitHub will create the branch from a fork automatically.

Use Go 1.22 or later. Please discuss breaking changes to the public API in an issue first.
