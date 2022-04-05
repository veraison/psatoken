# Features

This is a compliant implementation of two specifications:

* [draft-tschofenig-rats-psa-token-07](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-07) (`PSA_IOT_PROFILE_1`), and 
* [draft-tschofenig-rats-psa-token-09](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-09) (`http://arm.com/psa/2.0.0`)

The package exposes the following functionalities:

* get / set claims in a profile independent way
* sign / verify (COSE_Sign1)

# Make targets

* `make test` (or just `make`) to run the unit tests;