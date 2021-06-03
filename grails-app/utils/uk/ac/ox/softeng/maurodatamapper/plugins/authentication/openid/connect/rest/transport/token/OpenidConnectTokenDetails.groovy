package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.token

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import groovy.json.JsonSlurper

import java.security.interfaces.RSAPublicKey

/**
 * @since 02/06/2021
 */
class OpenidConnectTokenDetails {

    String accessToken
    Integer expiresIn
    Integer refreshExpiresIn
    String refreshToken
    String tokenType
    String idToken
    Integer notBeforePolicy
    String sessionState
    String scope
    DecodedJWT decodedIdToken

    OpenidConnectTokenDetails(Map<String, Object> data) {
        accessToken = data.access_token
         expiresIn = data.expires_in as Integer
         refreshExpiresIn = data.refresh_expires_in as Integer
         refreshToken = data.refresh_token
         tokenType = data.token_type
         idToken = data.id_token
         notBeforePolicy = data['not-before-policy'] as Integer
         sessionState = data.session_tate
         scope = data.scope
        decodedIdToken = JWT.decode(idToken)
    }


}
