# Features

This is a compliant implementation of ~~three~~two specifications:

* [draft-tschofenig-rats-psa-token-07](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-07) (`PSA_IOT_PROFILE_1`), and 
* [draft-tschofenig-rats-psa-token-09](https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-09) (`http://arm.com/psa/2.0.0`)
* ~~Realm Management Monitor Specificiation [RMM Spec](https://developer.arm.com/documentation/den0137/latest)~~

> [!Note]
> Realm Management Monitor Specification implementation has been moved to
> [ccatoken](https://github.com/veraison/ccatoken).

The package exposes the following functionalities:

* get / set claims in a profile independent way
* validate the claims-set
* sign / verify (using COSE_Sign1) the claims-set

# Make targets

* `make test` (or just `make`) to run the unit tests;

# Implementing new profiles

It is possible to support PSA-derived profiles other than profiles 1 and 2
implemented here. To do this you need to provide an implementation of `IClaims`
and an implementation of `IProfile` that associates your `IClaims`
implementation with an `eat.Profile` value, and then register the `IProfile`
implementation using `RegisterProfile()`. The simplest way to implement
`IClaims` is to embed one of the existing implementations. Please refer to [the
example](example_extensions_test.go) for details.
