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

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.core.container.Folder
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token.OpenidConnectToken
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.util.logging.Slf4j
import org.jsoup.Connection
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.FormElement
import spock.lang.Ignore

import java.time.Duration
import javax.servlet.ServletContext
import javax.servlet.http.HttpSession

import static io.micronaut.http.HttpStatus.NOT_FOUND
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
    SessionService sessionService
    ServletContext servletContext
    GrailsApplication grailsApplication

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
    String getFolderId() {
        Folder.findByLabel('Functional Test Folder').id.toString()
    }

    @Transactional
    CatalogueUser getUser(String emailAddress) {
        CatalogueUser.findByEmailAddress(emailAddress)
    }

    @Transactional
    void removeRefreshTokenForUserToken(String emailAddress) {
        OpenidConnectToken token = OpenidConnectToken.byEmailAddress(emailAddress).get()
        token.refreshToken = null
        token.refreshExpiresIn = null
        token.save(flush: true)
    }

    @Transactional
    void updateKeycloakProviderMaxAge(Long maxAge) {
        OpenidConnectProvider provider = OpenidConnectProvider.findByLabel(BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        provider.authorizationEndpointParameters.maxAge = maxAge
        provider.save(flush: true)
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

        when: 'grab the session created'
        HttpSession session = servletContext.getAttribute(SessionService.CONTEXT_PROPERTY_NAME).values().find{it.getAttribute('emailAddress') == StandardEmailAddress.ADMIN}

        then: 'session timeout has been overridden to 24hrs which is the default for this plugin'
        session.maxInactiveInterval == Duration.ofHours(24).seconds
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

    void 'KEYCLOAK08 - test logging in with valid authentication code and altered max_age'() {
        given:
        updateKeycloakProviderMaxAge(1)
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')

        when: 'in call made to login'
        sleep(2000)
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)

        cleanup:
        updateKeycloakProviderMaxAge(null)
    }

    void 'KEYCLOAK09 - test access inside timeout'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder available'
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK10 - test access after timeout with no refresh token'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'removing refresh token'
        removeRefreshTokenForUserToken('admin@maurodatamapper.com')

        and: 'getting folder'
        sleep(65000)
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out and unauthorised'
        verifyResponse(UNAUTHORIZED, response)

        when: 'getting folder'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'expected response for unlogged in user'
        verifyResponse(NOT_FOUND, response)
    }

    void 'KEYCLOAK11 - test access after timeout with refresh token'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'getting folder'
        sleep(65000)
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out and unauthorised'
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK12 - test access after session invalidated'() {

        when: 'not logged in'
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'folder is not available'
        verifyResponse(NOT_FOUND, response)

        when: 'logged in'
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak('mdm-admin', 'mdm-admin')
        POST('login?scheme=openIdConnect', authorizeResponse)
        verifyResponse(OK, response)

        and: 'timeout session'
        HttpSession session = servletContext.getAttribute(SessionService.CONTEXT_PROPERTY_NAME).values().find{it.getAttribute('emailAddress') == StandardEmailAddress.ADMIN}
        session.setMaxInactiveInterval(2)

        and: 'getting folder'
        sleep(5000)
        GET("folders/${folderId}", MAP_ARG, true)

        then: 'session timed out folder is not available\''
        verifyResponse(NOT_FOUND, response)
    }

    @Ignore('Manual testing only')
    void 'GOOGLE01 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        // Manually go to this web URL
        /*
https://accounts.google.com/o/oauth2/v2/auth?scope=openid+email&response_type=code&state=9329705d-3cd0-4a59-b588-a369d72aaeae&nonce=0c20ec52-b581-4044-a436-25c5fbea141c
&client_id=375980182300-tc8sb8c1jelomnkmvqtkkqpl4g8lkp06.apps.googleusercontent.com&redirect_uri=https://jenkins.cs.ox.ac.uk
        */
        // Get the redirected URL
        /*
        https://jenkins.cs.ox.ac.uk/?
        state=9329705d-3cd0-4a59-b588-a369d72aaeae
        &code=4%2F0AY0e-g4c0Mjf20NX6c430OSvXx9cvezF8yQsNQwY0cPn-TZ024JjR--PAdmBafoU4h92qA
        &scope=email+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email
        &authuser=0
        &prompt=consent
        */
        // Extract the code param and put in the map below
        // Run the test
        // Each time you run you will need to get a new code
        Map<String, String> authorizeResponse = [
            openidConnectProviderId: googleProvider.id.toString(),
            nonce                  : '0c20ec52-b581-4044-a436-25c5fbea141c',
            redirect_uri           : 'https://jenkins.cs.ox.ac.uk',
            state                  : '9329705d-3cd0-4a59-b588-a369d72aaeae',
            code                   : '4%2F0AY0e-g6w7HkOLFe3kfPV5BVyoIqpwQ4McRhV_UGr8RxnQXvpVvAMPSkROqTtyM1cCm6KBA',
        ]

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)

        when: 'check user has been created'
        CatalogueUser user = getUser('ollie.freeman@gmail.com')

        then:
        user
        user.firstName == 'Ollie'
        user.lastName == 'Freeman'
        user.createdBy == 'openidConnectAuthentication@jenkins.cs.ox.ac.uk'
    }

    Map<String, String> authoriseAgainstKeyCloak(String username = 'mdm-admin', String password = 'mdm-admin') {
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
        authenticateParameters.nonce = documentData.nonce
        authenticateParameters
    }

    Map<String, Object> getAuthoriseDocument(OpenidConnectProvider provider) {

        // Connect and then request the authorise page from KC
        String authoriseEndpoint = provider.getFullAuthorizationEndpointUrl()

        // Get all the parameters we sent to authorise
        Map<String, String> authorizeParameters = authoriseEndpoint.toURL().query.split('&').collectEntries {it.split('=')}

        // Pull out the nonce
        String redirectUrl = "https://jenkins.cs.ox.ac.uk"
        String authoriseEndpointWithRedirect = "${authoriseEndpoint}&redirect_uri=${URLEncoder.encode(redirectUrl, 'UTF-8')}"

        Connection authoriseConnection = Jsoup.connect(authoriseEndpointWithRedirect)
        [document   : authoriseConnection.get(),
         cookies    : authoriseConnection.response().cookies(),
         redirectUrl: redirectUrl,
         nonce      : authorizeParameters.nonce
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
