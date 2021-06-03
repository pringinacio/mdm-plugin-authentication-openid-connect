package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.OpenidConnectAuthenticationDetails
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.token.OpenidConnectTokenDetails

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.Claim
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.interfaces.Verification

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @since 02/06/2021
 */
class OpenidConnectIdTokenJwtVerifier {

    final JWTVerifier jwtVerifier

    final DecodedJWT decodedIdToken
    final String providerLabel
    final String tokenSessionState
    final String authenticationSessionState
    final OpenidConnectProvider openidConnectProvider
    final Long maxAgeOfAuthentication

    OpenidConnectIdTokenJwtVerifier(OpenidConnectProvider openidConnectProvider, OpenidConnectTokenDetails tokenDetails,
                                    OpenidConnectAuthenticationDetails authenticationDetails) {
        this.decodedIdToken = tokenDetails.decodedIdToken
        this.providerLabel = openidConnectProvider.label
        this.openidConnectProvider = openidConnectProvider
        this.tokenSessionState = tokenDetails.sessionState
        this.authenticationSessionState = authenticationDetails.sessionState
        this.maxAgeOfAuthentication = openidConnectProvider.authenticationRequestParameters.maxAge

        JwkProvider provider = new UrlJwkProvider(openidConnectProvider.discoveryDocument.jwksUri.toURL())
        Jwk jsonWebKey = provider.get(decodedIdToken.keyId)
        Algorithm algorithm = getJwkAlgorithm(jsonWebKey)

        Verification verification = JWT.require(algorithm)
            .withIssuer(openidConnectProvider.discoveryDocument.issuer)
            .withAudience(openidConnectProvider.clientId)
            .withClaim('session_state', tokenDetails.sessionState)
            .withClaim('nonce', authenticationDetails.nonce)
            .withClaimPresence('email')

        if (decodedIdToken.audience.size() > 1) {
            verification = verification.withClaim('azp', openidConnectProvider.clientId)
        }

        if (maxAgeOfAuthentication != null) {
            verification = verification.withClaimPresence('auth_time')
        }

        jwtVerifier = verification.build()
    }

    @SuppressWarnings('GroovyVariableNotAssigned')
    void verify() throws JWTVerificationException {
        // Initial plain jwt verification
        // 1,2,3,4,5,6,7,9,10,11
        jwtVerifier.verify(decodedIdToken)

        // 12 (acr) out of scope

        // 13
        Claim authTime = decodedIdToken.getClaim('auth_time')
        Date now = new Date()
        now.setTime((now.getTime() / 1000 * 1000) as long); // truncate millis
        Date agedDate = new Date(authTime.asDate().getTime() + maxAgeOfAuthentication * 1000)
        if (now.after(agedDate)) throw new JWTVerificationException("Authentication code can't be used after ${agedDate}")

        // Addtl
        if (tokenSessionState != authenticationSessionState) throw new JWTVerificationException('Token session_state must match authentication session_state')
    }

    Algorithm getJwkAlgorithm(Jwk jwk) {
        switch (jwk.algorithm) {
            case 'RS256':
                return Algorithm.RSA256((RSAPublicKey) jwk.publicKey, null)
            case 'RS384':
                return Algorithm.RSA384((RSAPublicKey) jwk.publicKey, null)
            case 'RS512':
                return Algorithm.RSA512((RSAPublicKey) jwk.publicKey, null)
            case 'ES256':
                return Algorithm.ECDSA256((ECPublicKey) jwk.publicKey, null)
            case 'ES384':
                return Algorithm.ECDSA384((ECPublicKey) jwk.publicKey, null)
            case 'ES512':
                return Algorithm.ECDSA512((ECPublicKey) jwk.publicKey, null)
            default:
                // verification 8 fail here
                throw new ApiBadRequestException('OCASXX', "Unsupported JWK Algorithm [${jwk.algorithm}] used by provider [${providerLabel}]")

        }
    }
}
