# Jwt Token Creation

### Generate key pair:
```bash
# Generate key pair and convert to PEM format
make gen-keys

```
### Token will be generated from private key file
### Default expiry time is 5 minutes

### Generate jwt token with claims:
```bash
make gen-token
# token will be printed on terminal
```

### Token is validated with the public key file to get the claims