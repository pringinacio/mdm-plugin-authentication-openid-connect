package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport


import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT

/**
 * @since 02/06/2021
 */
class TokenResponseBody {

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

    TokenResponseBody(Map<String, Object> data) {
        accessToken = data.access_token
        expiresIn = data.expires_in as Integer
        refreshExpiresIn = data.refresh_expires_in as Integer
        refreshToken = data.refresh_token
        tokenType = data.token_type
        idToken = data.id_token
        notBeforePolicy = data['not-before-policy'] as Integer
        sessionState = data.session_state
        scope = data.scope
        decodedIdToken = JWT.decode(idToken)
    }
}
