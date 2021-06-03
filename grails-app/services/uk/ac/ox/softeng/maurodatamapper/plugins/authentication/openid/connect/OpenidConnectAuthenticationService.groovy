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

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt.OpenidConnectIdTokenJwtVerifier
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.OpenidConnectAuthenticationDetails
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.token.OpenidConnectTokenDetails
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService

import com.auth0.jwt.exceptions.JWTVerificationException
import grails.gorm.transactions.Transactional
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException

/**
 * https://auth0.com/docs/flows/authorization-code-flow
 * https://www.keycloak.org/docs/latest/securing_apps/index.html#endpoints
 *
 */
@Transactional
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
        log.info('Attempt to access system using OpenId Connect')

        OpenidConnectAuthenticationDetails authenticationDetails = new OpenidConnectAuthenticationDetails(authenticationInformation)

        OpenidConnectProvider openidConnectProviderProvider = openidConnectProviderService.get(authenticationDetails.openidConnectProvider)

        if (!openidConnectProviderProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        CatalogueUser user

        try {
            HttpRequest<Map> request = HttpRequest.POST(openidConnectProviderProvider.accessTokenEndpoint,
                                                        openidConnectProviderProvider.getAccessTokenRequestParameters(authenticationDetails.code))
                .basicAuth('client_secret', openidConnectProviderProvider.clientSecret)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                .accept(MediaType.APPLICATION_JSON_TYPE)

            HttpResponse<Map> response = HttpClient
                .create(openidConnectProviderProvider.issuerUrl.toURL())
                .toBlocking()
                .exchange(request, Argument.of(Map)
                )

            OpenidConnectTokenDetails tokenDetails = new OpenidConnectTokenDetails(response.body())

            OpenidConnectIdTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(openidConnectProviderProvider, tokenDetails, authenticationDetails)

            try{
                verifier.verify()
            }catch(JWTVerificationException exception){
                log.warn("${exception.message}")
                return null
            }

            String emailAddress = tokenDetails.decodedIdToken.getClaim('email').asString()

            user = catalogueUserService.findByEmailAddress(emailAddress)

            if (!user) {
                user = catalogueUserService.createNewUser(emailAddress: emailAddress,
                                                          password: null,
                                                          createdBy: "openidConnectAuthentication@${openidConnectProviderProvider.issuerUrl.toURL().host}",
                                                          pending: false, firstName: "Unknown", lastName: 'Unknown')

                if (!user.validate()) throw new ApiInvalidModelException('OCAS02:', 'Invalid user creation', user.errors)
                user.save(flush: true, validate: false)
                user.addCreatedEdit(user)
            }

        }
        catch (HttpClientResponseException e) {
            switch (e.status) {
                case HttpStatus.UNAUTHORIZED:
                    return null
                case HttpStatus.FORBIDDEN:
                    return null
                default:
                    throw new ApiBadRequestException('OCAS03:', "Could not authenticate against Openid Connect Provider: \n${e.response.body()}", e)
            }
        }

        user
    }

}
