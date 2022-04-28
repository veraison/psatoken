# Features

Compliant implementation of [draft-tschofenig-rats-psa-token-08](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-08) with the following features:

* sign / verify (CWT using COSE Sign1)
* CBOR encoder / decoder
* JSON encoder


# Make targets

* `make test` (or just `make`) to run the unit tests;
* `make coverage` to get code coverage stats;
* `make lint` to run the code linter (requires [golangci-lint](https://golangci-lint.run/usage/install/);
* `make docker` creates a docker image of the psatoken CLI

## Docker image

The image, tagged `psatoken-client:latest` runs the `psatoken-client` CLI with default arguments.
The arguments can be controlled using the following environment variables:

* `APIURL` corresponds to `-url`
* `KEYFILE` corresponds to `-key`
* `CLAIMSFILE` corresponds to `-claims`

For example to connect the client to an API server running on the host's loopback interface:

```
docker run \
    -e APIURL="http://host.docker.internal:8888/challenge-response/v1/newSession" \
    -e KEYFILE=/path/to/my/ecdsa/private/key/in/jwk/format \
    -e CLAIMSFILE=/path/to/my/claims/template/in/json/format \
    psatoken-client
```

# An Experiment in Type Enrichment

The JSON encoder "decorates" the token with extra `_`-prefixed `desc`-postfixed fields:
```
{
  "partition-id": 1,
  "_partition-id-desc": "spe",
  "security-life-cycle": 12288,
  "_security-lifecycle-desc": "secured",
  ...
}
```
