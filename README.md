# moonshot_ecp_test
This is a demo, based on dockerized-idp-testbed, demonstrating how to configure a Moonshot IDP (FreeRADIUS) to use SAML ECP
to authenticate users and get a SAML Assertion.

## How to test
1. Build and execute the environment using `docker-compose --build up` on a terminal.
1. On a different terminal, run `docker-compose exec moonshot_idp moonshot_tester`.
1. When the Moonshot UI prompts, use the `alice@test.org` identity with `password` password (this can be customised in the `./ldap/users.ldif`).


