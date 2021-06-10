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
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.AuthorizationResponseParameters
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser

import com.auth0.jwt.exceptions.JWTVerificationException
import grails.gorm.transactions.Transactional

@Transactional
class OpenidConnectTokenService {

    OpenidConnectProviderService openidConnectProviderService

    void delete(OpenidConnectToken openidConnectToken) {
        openidConnectToken.delete(flush: true)
    }

    OpenidConnectToken findByCatalogueUser(CatalogueUser catalogueUser) {
        OpenidConnectToken.findByCatalogueUser(catalogueUser)
    }

    OpenidConnectToken createToken(OpenidConnectProvider openidConnectProvider, Map<String, Object> tokenResponseBody) {
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
            )
    }

    void validateAndSave(OpenidConnectToken openidConnectToken) {
        if (!openidConnectToken.validate()) {
            throw new ApiInvalidModelException('OCTSS02', 'Could not update and store openid connect token', openidConnectToken.errors)
        }
        openidConnectToken.save(validate: false, flush: true)
    }

    boolean verifyIdToken(OpenidConnectToken token, AuthorizationResponseParameters authorizationResponseParameters) {
        OpenidConnectIdTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(token, authorizationResponseParameters.nonce,
                                                                                       authorizationResponseParameters.sessionState)
        try {
            verifier.verify()
            true
        } catch (JWTVerificationException exception) {
            log.warn("Access token failed verification: ${exception.message}")
            return false
        }
    }

    boolean verifyIdTokenForUser(CatalogueUser catalogueUser) {
        OpenidConnectToken token = findByCatalogueUser(catalogueUser)
        OpenidConnectIdTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(token, null, null)

        try {
            verifier.verify()
        } catch (JWTVerificationException exception) {
            log.warn("Access token failed verification: ${exception.message}")
            false
        }
        true
    }

    void refreshToken() {
        /*
        grant_type : "refresh_token"
        client_id
        client_secret
        refresh_token : the refresh token from the original request

        same process as loadToken but using these in the body
         */

    }
}
