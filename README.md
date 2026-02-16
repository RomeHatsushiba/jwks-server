JWKS Server



Author: Rome Hatsushiba

Language: Go (Golang)



Description



This project implements a RESTful JWKS (JSON Web Key Set) server that generates RSA key pairs and issues JSON Web Tokens (JWTs).

The server provides public keys for verification and returns signed authentication tokens for a mock user.



The server supports key expiration and can intentionally issue expired tokens for testing.



Features



RSA 2048 key generation



kid (key identifier) support



JWKS endpoint serving only valid keys



JWT authentication endpoint



Expired JWT issuance (?expired=true)



Automated tests (>80% coverage)



Endpoints

Get Public Keys

GET /.well-known/jwks.json



Get Valid Token

POST /auth



Get Expired Token

POST /auth?expired=true



Run the Server

go run .





Server runs on:



http://localhost:8080



Example Requests

curl http://localhost:8080/.well-known/jwks.json

curl -X POST http://localhost:8080/auth

curl -X POST "http://localhost:8080/auth?expired=true"



Tests



Run:



go test ./... -cover





Coverage is above 80%.

