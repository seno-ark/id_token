# id_token
Golang OpenID id_token validator

## Installation Guidelines

Install the id_token package
```sh
go get -u github.com/seno-ark/id_token
```

Import it in your code:
```go
import "github.com/seno-ark/id_token"
```

## Usage
```go

idToken := "<user id token>"

validator, err := id_token.NewValidator(&id_token.Config{
    Provider: id_token.GOOGLE,
    ClientID: "<your google client id>",
})
if err != nil {
    panic(err)
}

payload, err := validator.Validate(idToken)
if err != nil {
    switch err {
    case id_token.ErrAudienceNotMatch:
        fmt.Println("ERROR: Audience is not match")
    case id_token.ErrTokenExpired:
        fmt.Println("ERROR: Token was expired")
    default:
        fmt.Println("ERROR: Invalid token")
    }
}

fmt.Printf("id_token payload: %+v", payload)
```