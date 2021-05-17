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
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticationSchemeService
import uk.ac.ox.softeng.maurodatamapper.util.Utils

import grails.gorm.transactions.Transactional
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException

import java.net.http.HttpResponse
import javax.servlet.http.HttpSession

@Transactional
class OpenidConnectAuthenticatingService implements AuthenticationSchemeService {

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
        log.info('Attempt to access system using OAUTH')

        HttpSession session = authenticationInformation.session
        String oauthProviderString = authenticationInformation.oauthProviderString
        String accessCode = authenticationInformation.accessCode

        OpenidConnectProvider openidConnectProviderProvider = openidConnectProviderService.get(Utils.toUuid(oauthProviderString))

        if (!openidConnectProviderProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        CatalogueUser user

        // TODO how does this change for each individual user...you're not using the session info??
        // TODO there is a slightly neater way to do all this client stuff which i've learnt from the test frameworks and also the fhir plugin work
        // but i'm not bothered about this at the moment, it'll just be something to look at after we get it all working
        try {
            HttpResponse response = HttpClient
                .create(openidConnectProviderProvider.baseUrl.toURL())
                .toBlocking()
                .exchange(
                    HttpRequest.POST(openidConnectProviderProvider.accessTokenRequestUrl, openidConnectProviderProvider.accessTokenRequestParameters)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                        .accept(MediaType.APPLICATION_JSON_TYPE)
                )

            if (openidConnectProviderProvider.accessTokenRequestParameters["state"] != response.properties["state"]){
                throw new SecurityException('OCAS01:', 'The response state does not match the request state.')
            }

            Map idTokenJson = Base64.decodeBase64(response.body().getAt("id_token"))

            String emailAddress = idTokenJson.get("email")

            user = catalogueUserService.findByEmailAddress(emailAddress)

            if (!user) {
                user = catalogueUserService.createNewUser(  emailAddress: emailAddress,
                                                            password: null,
                                                            createdBy: "openidConnectAuthentication@${openidConnectProviderProvider.baseUrl.toURL().host}",
                                                            pending: false, firstName: "Unknown", lastName: 'Unknown')

                if (!user.validate()) throw new ApiInvalidModelException('OCAS02:', 'Invalid user creation', user.errors)
                user.save(flush: true, validate: false)
                user.addCreatedEdit(user)
            }

        }
        catch (HttpClientResponseException e){
            switch (e.status){
                case HttpStatus.UNAUTHORIZED:
                    return null
                case HttpStatus.BAD_REQUEST:
                    throw new ApiBadRequestException('OCAS02:', 'Could not authenticate against OAUTH Provider due to a bad request')
                default:
                    throw new ApiInternalException('OCAS03:', "Could not authenticate against OAUTH Provider: ${e.getStatus()} ${e.getMessage()}", e)
            }
        }

        user

    }

}
