# mdm-plugin-authentication-openid-connect

| Branch | Build Status |
| ------ | ------------ |
| master | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-openid-connect%2Fmaster)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-openid-connect/branches) |
| develop | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-openid-connect%2Fdevelop)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-openid-connect/branches) |

## Requirements

* Java 12 (AdoptOpenJDK)
* Grails 4.0.3+
* Gradle 6.5+

All of the above can be installed and easily maintained by using [SDKMAN!](https://sdkman.io/install).

## Applying the Plugin

The preferred way of running Mauro Data Mapper is using the [mdm-docker](https://github.com/MauroDataMapper/mdm-docker) deployment. However you can
also run the backend on its own from [mdm-application-build](https://github.com/MauroDataMapper/mdm-application-build).

### mdm-docker

In the `docker-compose.yml` file add:

```yml
mauro-data-mapper:
    build:
        args:
            ADDITIONAL_PLUGINS: "uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-openid-connect:1.0.0-SNAPSHOT"
```

Please note, if adding more than one plugin, this is a semicolon-separated list

### mdm-application-build

In the `build.gradle` file add:

```groovy
grails {
    plugins {
        runtimeOnly 'uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-openid-connect:1.0.0-SNAPSHOT'
    }
}
```

## Workflow

Described by https://auth0.com/docs/flows/authorization-code-flow

1. UI requests known providers from us
2. User clicks link provided by UI
   * UI has to add the `redirect_uri` url param to the url
3. User is taken to authentication request url
4. User authenticates
5. Auth returns response with params in url
    * session_state 
    * code 
    * state 
6. UI sends these params to API as the body of a login request
    * session_state
    * code
    * state
    * redirect_uri = exact uri used by UI
    * nonce (sent from API but dynamically created each time so API doesnt know what it is)
7. API calls the access token endpoint using these parameters as a urlencoded form post 
   (also use basic auth header with username: `client_secret`,password: `$clientSecret`)
    * client_id
    * client_secret
    * grant_type
    * code
    * redirect_uri
    * session_state
8. Response back in JSON form
    * access_token
    * expires_in
    * refresh_expires_in
    * token_type
    * id_token
    * not-before-policy
    * session_state
    * scope
    


Notes:

The API supplies all of the authentication url prebuilt and requires the UI to add the `redirect_uri` parameter

## Openid Connect Specifications

### Authorisation Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

### Access Token Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

A failed attempt will nullify the code returned by the UI, requiring a request for a new code

### User Information Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

### Client Authentication

https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

## Provider Specific Documentation

### Keycloak Documentation

https://www.keycloak.org/docs/latest/securing_apps/index.html#endpoints

### Google Documentation

https://developers.google.com/identity/protocols/oauth2/openid-connect

Note that refresh token is not sent as the access token has a 51min expiry life and therefore is unlikely to be needed.
I believe that making any access check request "resets" the expiry counter but this will need to be checked
It may also be the same for Keycloak with the "reset"