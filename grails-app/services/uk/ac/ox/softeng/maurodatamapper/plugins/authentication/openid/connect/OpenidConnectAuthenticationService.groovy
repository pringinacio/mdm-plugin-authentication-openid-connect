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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt.OpenidConnectIdTokenJwtVerifier
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.AuthorizationResponseParameters
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.TokenResponseBody
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService

import com.auth0.jwt.exceptions.JWTVerificationException
import grails.gorm.transactions.Transactional
import groovy.util.logging.Slf4j
/**
 * https://auth0.com/docs/flows/authorization-code-flow
 * https://www.keycloak.org/docs/latest/securing_apps/index.html#endpoints
 *
 */
@Transactional
@Slf4j
class OpenidConnectAuthenticationService implements AuthenticationSchemeService {

    OpenidConnectProviderService openidConnectProviderService

    CatalogueUserService catalogueUserService

    SessionService sessionService


    @Override
    String getName() {
        'openIdConnect'
    }

    @Override
    String getDisplayName() {
        'OpenId Connect Authentication Service'
    }

    @Override
    int getOrder() {
        0
    }

    @Transactional
    CatalogueUser authenticateAndObtainUser(Map<String, Object> authenticationInformation) {
        log.info('Attempt to authenticate system using Openid Connect')

        AuthorizationResponseParameters authorizationResponseParameters = new AuthorizationResponseParameters(authenticationInformation)

        OpenidConnectProvider openidConnectProvider = openidConnectProviderService.get(authorizationResponseParameters.openidConnectProviderId)

        if (!openidConnectProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        Map<String, Object> responseBody = openidConnectProviderService.loadTokenFromOpenidConnectProvider(openidConnectProvider,
                                                     openidConnectProvider.getAccessTokenRequestParameters(authorizationResponseParameters.code,
                                                                                                           authorizationResponseParameters.redirectUri,
                                                                                                           authorizationResponseParameters.sessionState)
        )

        if (!responseBody) {
            log.warn("Failed to get access token from Openid Connect Provider [${openidConnectProvider.label}]")
            return null
        }

        TokenResponseBody tokenDetails = new TokenResponseBody(responseBody)

        OpenidConnectIdTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(openidConnectProvider, tokenDetails, authorizationResponseParameters)

        try {
            verifier.verify()
        } catch (JWTVerificationException exception) {
            log.warn("Access token failed verification: ${exception.message}")
            return null
        }

        String emailAddress = tokenDetails.decodedIdToken.getClaim('email').asString()

        CatalogueUser user = catalogueUserService.findByEmailAddress(emailAddress)

        if (!user) {
            log.info('Creating new user {}', emailAddress)
            URL issuerUrl = openidConnectProvider.discoveryDocument.issuer.toURL()
            user = catalogueUserService.createNewUser(emailAddress: emailAddress,
                                                      password: null,
                                                      createdBy: "openidConnectAuthentication@${issuerUrl.authority}",
                                                      pending: false, firstName: "Unknown", lastName: 'Unknown')

            if (!user.validate()) throw new ApiInvalidModelException('OCAS02:', 'Invalid user creation', user.errors)
            user.save(flush: true, validate: false)
            user.addCreatedEdit(user)
        }

        user
    }
}
