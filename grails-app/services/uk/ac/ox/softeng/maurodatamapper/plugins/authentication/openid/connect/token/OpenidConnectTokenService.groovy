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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt.OpenidConnectIdTokenJwtVerifier
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt.OpenidConnectTokenJwtVerifier
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser

import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import grails.gorm.transactions.Transactional
import groovy.util.logging.Slf4j

import javax.servlet.http.HttpSession

@Slf4j
@Transactional
class OpenidConnectTokenService {

    static final String ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME='openidAccessExpiry'
    static final String REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME='openidRefreshExpiry'
    static final String OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME='openidAuthentication'

    OpenidConnectProviderService openidConnectProviderService

    void delete(OpenidConnectToken openidConnectToken) {
        openidConnectToken.delete(flush: true)
    }

    OpenidConnectToken findByCatalogueUser(CatalogueUser catalogueUser) {
        OpenidConnectToken.findByCatalogueUser(catalogueUser)
    }

    OpenidConnectToken findByEmailAddress(String emailAddress) {
        OpenidConnectToken.byEmailAddress(emailAddress).get()
    }

    void deleteByEmailAddress(String emailAddress) {
        OpenidConnectToken.byEmailAddress(emailAddress).deleteAll()
    }

    OpenidConnectToken createToken(OpenidConnectProvider openidConnectProvider, Map<String, Object> tokenResponseBody, String nonce) {
        new OpenidConnectToken(
            openidConnectProvider: openidConnectProvider,
            accessToken: tokenResponseBody.access_token,
            expiresIn: tokenResponseBody.expires_in as Integer,
            refreshExpiresIn: tokenResponseBody.refresh_expires_in as Integer,
            refreshToken: tokenResponseBody.refresh_token,
            tokenType: tokenResponseBody.token_type,
            idToken: tokenResponseBody.id_token,
            notBeforePolicy: tokenResponseBody['not-before-policy'] as Integer,
            sessionState: tokenResponseBody.session_state,
            scope: tokenResponseBody.scope,
            nonce: nonce,
            )
    }

    void validateAndSave(OpenidConnectToken openidConnectToken) {
        if (!openidConnectToken.validate()) {
            throw new ApiInvalidModelException('OCTSS02', 'Could not update and store openid connect token', openidConnectToken.errors)
        }
        openidConnectToken.save(validate: false, flush: true)
    }

    boolean verifyIdToken(OpenidConnectToken token, String lastKnownSessionState) {
        OpenidConnectTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(token, lastKnownSessionState)
        try {
            verifier.verify()
            true
        } catch (JWTVerificationException exception) {
            log.warn("Token failed verification: ${exception.message}")
            return false
        }
    }

    boolean hasRefreshTokenExpired(OpenidConnectToken token) {
        if (token.decodedRefreshToken) {
            hasJwtTokenExpired(token.decodedRefreshToken)
        }
        log.warn('Non-JWT refresh tokens are not currently supported')
        false
    }

    boolean hasAccessTokenExpired(OpenidConnectToken token) {
        if (token.decodedIdToken) {
            return hasJwtTokenExpired(token.decodedIdToken)
        }
        log.warn('Non-JWT refresh tokens are not currently supported')
        false
    }

    OpenidConnectToken refreshTokenByEmailAddress(String emailAddress) {
        refreshToken(findByEmailAddress(emailAddress))
    }

    OpenidConnectToken refreshToken(OpenidConnectToken openidConnectToken) {
        log.debug('Refreshing token for [{}]', openidConnectToken.catalogueUser.emailAddress)
        OpenidConnectProvider provider = openidConnectToken.openidConnectProvider
        Map<String, Object> responseBody = openidConnectProviderService.loadTokenFromOpenidConnectProvider(
            provider,
            provider.getAccessTokenRefreshRequestParameters(openidConnectToken.refreshToken)
        )
        if (!responseBody) {
            log.warn("Failed to refresh access token for [${openidConnectToken.catalogueUser.emailAddress}]")
            return null
        }

        if (responseBody.error) {
            log.warn("Failed to refresh access token for [${openidConnectToken.catalogueUser.emailAddress}] because [${responseBody.error_description}]")
            return null
        }

        String previousSessionState = openidConnectToken.sessionState
        openidConnectToken.tap {
            accessToken = responseBody.access_token
            refreshToken = responseBody.refresh_token
            idToken = responseBody.id_token
            sessionState = responseBody.session_state
        }

        if (!verifyIdToken(openidConnectToken, previousSessionState)) {
            log.warn("Failed to refresh access token for [${openidConnectToken.catalogueUser.emailAddress}] as validation on refreshed token failed")
            return null
        }
        log.debug('Validating and saving refreshed token')
        validateAndSave(openidConnectToken)
        openidConnectToken
    }

    void storeDataIntoHttpSession(OpenidConnectToken openidConnectToken, HttpSession session){
        session.setAttribute(OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME, true)
        session.setAttribute(ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME, openidConnectToken.getAccessTokenExpiry())
        session.setAttribute(REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME, openidConnectToken.getRefreshTokenExpiry())
    }

    private boolean hasJwtTokenExpired(DecodedJWT token) {
        Date expiresAt = token.expiresAt
        Date now = new Date()
        now = new Date((now.getTime() / 1000).toLong() * 1000) // truncate millis
        return now.after(expiresAt)
    }
}