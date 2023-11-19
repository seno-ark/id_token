# id_token
OpenID id_token validator

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
    panic(err)
}

fmt.Println("id_token payload:", payload)
```