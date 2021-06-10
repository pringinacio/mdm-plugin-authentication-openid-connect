/*
 * Copyright 2020-2021 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken

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
import groovy.util.logging.Slf4j

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
/**
 * https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @since 02/06/2021
 */
@Slf4j
class OpenidConnectIdTokenJwtVerifier {

    final JWTVerifier jwtVerifier

    final DecodedJWT decodedIdToken
    final String providerLabel
    final String tokenSessionState
    final String authorisationSessionState
    final OpenidConnectProvider openidConnectProvider
    final Long maxAgeOfAuthentication

    OpenidConnectIdTokenJwtVerifier(OpenidConnectToken token, String nonce, String authorisationSessionState) {
        this.decodedIdToken = token.decodedIdToken
        this.providerLabel = token.openidConnectProvider.label
        this.openidConnectProvider = token.openidConnectProvider
        this.tokenSessionState = token.sessionState
        this.authorisationSessionState = authorisationSessionState
        this.maxAgeOfAuthentication = openidConnectProvider.authorizationEndpointParameters.maxAge

        JwkProvider provider = new UrlJwkProvider(openidConnectProvider.discoveryDocument.jwksUri.toURL())
        Jwk jsonWebKey = provider.get(decodedIdToken.keyId)
        Algorithm algorithm = getJwkAlgorithm(jsonWebKey)

        Verification verification = JWT.require(algorithm)
            .withIssuer(openidConnectProvider.discoveryDocument.issuer)
            .withAudience(openidConnectProvider.clientId)
            .withClaimPresence('email')

        if (decodedIdToken.audience.size() > 1) {
            log.debug('Adding azp verification')
            verification.withClaim('azp', openidConnectProvider.clientId)
        }

        if (tokenSessionState)
            log.debug('Adding session_state verification')
            verification.withClaim('session_state', tokenSessionState)

        if (nonce) {
            log.debug('Adding nonce verification')
            verification.withClaim('nonce', nonce)
        }

        if (maxAgeOfAuthentication != null) {
            log.debug('Adding auth_time verification')
            verification.withClaimPresence('auth_time')
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
        if (maxAgeOfAuthentication) {
            Claim authTime = decodedIdToken.getClaim('auth_time')
            Date now = new Date()
            now.setTime((now.getTime() / 1000 * 1000) as long); // truncate millis
            Date agedDate = new Date(authTime.asDate().getTime() + maxAgeOfAuthentication * 1000)
            if (now.after(agedDate)) throw new JWTVerificationException("Authentication code can't be used after ${agedDate}")
        }

        // Addtl
        if (tokenSessionState != authorisationSessionState) throw new JWTVerificationException('Token session_state must match authentication session_state')
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
