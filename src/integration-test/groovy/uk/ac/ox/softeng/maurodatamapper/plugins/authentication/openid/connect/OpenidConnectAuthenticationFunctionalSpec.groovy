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

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.util.logging.Slf4j
import org.jsoup.Connection
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.FormElement
import spock.lang.PendingFeature

import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED
/**
 *
 * <pre>
 * Controller: authenticating
 * |  POST  | /api/admin/activeSessions  | Action: activeSessionsWithCredentials
 * |  *     | /api/authentication/logout | Action: logout
 * |  POST  | /api/authentication/login  | Action: login
 * </pre>
 * @see uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingController
 */
@Slf4j
@Integration
class OpenidConnectAuthenticationFunctionalSpec extends BaseFunctionalSpec {

    CatalogueUserService catalogueUserService

    @OnceBefore
    @Transactional
    def checkAndSetupData() {

    }

    @Transactional
    void deleteUser(String id) {
        catalogueUserService.get(id).delete(flush: true)
    }

    @Transactional
    OpenidConnectProvider getKeycloakProvider() {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        provider.getFullAuthorizationEndpointUrl()
        provider
    }

    @Transactional
    OpenidConnectProvider getGoogleProvider() {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
        provider.getFullAuthorizationEndpointUrl()
        provider
    }

    @Transactional
    OpenidConnectProvider getMicrosoftProvider() {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME)
        provider.getFullAuthorizationEndpointUrl()
        provider
    }

    @Transactional
    CatalogueUser getUser(String emailAddress) {
        CatalogueUser.findByEmailAddress(emailAddress)
    }

    @Override
    String getResourcePath() {
        'authentication'
    }

    void 'PUBLIC - test getting public endpoint of providers'() {
        when:
        GET('openidConnectProviders', STRING_ARG, true)

        then:
        verifyResponse(OK, jsonCapableResponse)
        log.info('{}', jsonCapableResponse.body())
    }

    void 'KEYCLOAK01 - test logging in with empty authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.code = ''

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK02 - test logging in with random authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.code = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK03 - test logging in with no authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.remove('code')


        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK04 - test logging in with valid authentication code and invalid session_state'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.session_state = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK05 - test logging in with valid authentication code and invalid nonce'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()
        authorizeResponse.nonce = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK06 - test logging in with valid authentication code and parameters with existing user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK07 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('keycloak-only', 'keycloak-only')

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('keycloak-only@maurodatamapper.com')

        then:
        user
        user.firstName == 'keycloak-only'
        user.lastName == 'User'
        user.createdBy == 'openidConnectAuthentication@jenkins.cs.ox.ac.uk'
    }

    @PendingFeature
    void 'GOOGLE01 - test logging in with empty authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()
        authorizeResponse.code = ''

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE02 - test logging in with random authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()
        authorizeResponse.code = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE03 - test logging in with no authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()
        authorizeResponse.remove('code')


        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE04 - test logging in with valid authentication code and invalid session_state'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()
        authorizeResponse.session_state = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE05 - test logging in with valid authentication code and invalid nonce'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()
        authorizeResponse.nonce = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE06 - test logging in with valid authentication code and parameters with existing user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)
    }

    @PendingFeature
    void 'GOOGLE07 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstGoogle('google-only', 'google-only')

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('google-only@maurodatamapper.com')

        then:
        user
        user.firstName == 'google-only'
        user.lastName == 'User'
        user.createdBy == 'openidConnectAuthentication@jenkins.cs.ox.ac.uk'
    }

    Map<String, String> authoriseAgainstKeyCloak( String username = 'mdm-admin', String password = 'mdm-admin') {
        Map<String, Object> documentData = getAuthoriseDocument(keycloakProvider)

        // Get the login form and complete it
        FormElement form = (documentData.document as Document).getElementById('kc-form-login') as FormElement
        form.getElementById('username').val(username)
        form.getElementById('password').val(password)

        // Setup connection to submit form for authentication
        // We MUST submit the cookies from the authorise request along with the authenticate
        Connection connection = form.submit()
            .header('accept', '*/*')
            .cookies(documentData.cookies as Map<String, String>)

        // Execute and get the response
        // The response "url" will hold all the params we need to pass for token request
        Connection.Response response = connection.execute()

        // Get all the parameters we got back from authenticate
        Map<String, String> authenticateParameters = response.url().query.split('&').collectEntries {it.split('=')}
        authenticateParameters.openidConnectProviderId = keycloakProvider.id.toString()
        authenticateParameters.redirect_uri = documentData.redirectUrl
        authenticateParameters
    }


    Map<String, String> authoriseAgainstGoogle(String username = 'mdm-admin', String password = 'mdm-admin') {
        Map<String, Object> documentData = getAuthoriseDocument(googleProvider)
        assert false
        [:]
    }

    Map<String, Object> getAuthoriseDocument(OpenidConnectProvider provider) {

        // Connect and then request the authorise page from KC
        String authoriseEndpoint = provider.getFullAuthorizationEndpointUrl()

        // Get all the parameters we sent to authorise
        Map<String, String> authorizeParameters = authoriseEndpoint.toURL().query.split('&').collectEntries {it.split('=')}

        // Pull out the nonce
        String redirectUrl = "https://jenkins.cs.ox.ac.uk?nonce=${authorizeParameters.nonce}"
        String authoriseEndpointWithRedirect = "${authoriseEndpoint}&redirect_uri=${URLEncoder.encode(redirectUrl, 'UTF-8')}"

        Connection authoriseConnection = Jsoup.connect(authoriseEndpointWithRedirect)
        [document   : authoriseConnection.get(),
         cookies    : authoriseConnection.response().cookies(),
         redirectUrl: redirectUrl
        ]
    }

    Map<String, String> getResponseBody(String providerId, String code) {
        getResponseBody(providerId, code, UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString())
    }

    Map<String, String> getResponseBody(String providerId, String code, String sessionState, String nonce, String state) {
        [
            openidConnectProviderId: providerId,
            code                   : code,
            session_state          : sessionState,
            state                  : state,
            redirect_uri           : 'https://jenkins.cs.ox.ac.uk',
            nonce                  : nonce
        ]
    }
}
