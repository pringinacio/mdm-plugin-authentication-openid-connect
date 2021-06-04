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
import spock.lang.Ignore
import spock.lang.PendingFeature
import spock.lang.Stepwise

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
@Stepwise
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
        OpenidConnectProvider.findByLabel(BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
    }

    @Transactional
    OpenidConnectProvider getMicrosoftProvider() {
        OpenidConnectProvider.findByLabel(BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME)
    }

    @Transactional
    CatalogueUser getUser(String emailAddress){
        CatalogueUser.findByEmailAddress(emailAddress)
    }

    @Override
    String getResourcePath() {
        'authentication'
    }

    @Ignore
    void 'test getting public endpoint of providers'() {
        when:
        GET('openidConnectProviders', STRING_ARG, true)

        then:
        verifyResponse(OK, jsonCapableResponse)
        log.info('{}', jsonCapableResponse.body())
    }

    void 'KEYCLOAK01 - test logging in with empty authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)
        authorizeResponse.code = ''

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK02 - test logging in with random authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)
        authorizeResponse.code = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK03 - test logging in with no authentication code'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)
        authorizeResponse.remove('code')


        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK04 - test logging in with valid authentication code and invalid session_state'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)
        authorizeResponse.session_state = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK05 - test logging in with valid authentication code and invalid nonce'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)
        authorizeResponse.nonce = UUID.randomUUID().toString()

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK06 - test logging in with valid authentication code and parameters with existing user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider)

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', authorizeResponse)

        then:
        verifyResponse(OK, response)
    }

    void 'KEYCLOAK07 - test logging in with valid authentication code and parameters with non-existent user'() {
        given:
        Map<String, String> authorizeResponse = authoriseAgainstKeyCloak(keycloakProvider, 'keycloak-only','keycloak-only')

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
        when: 'in call made to login'
        POST('login?scheme=openIdConnect', [openidConnectProviderId: GoogleProviderId, code: ''])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE02 - test logging in with random authentication code'() {

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', [openidConnectProviderId: GoogleProviderId, code: UUID.randomUUID().toString()])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE03 - test logging in with no authentication code'() {
        when: 'in call made to login'
        POST('login?scheme=openIdConnect', [openidConnectProviderId: GoogleProviderId])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    @PendingFeature
    void 'GOOGLE04 - test logging in with  authentication code'() {
        when: 'in call made to login'
        POST('login?scheme=openIdConnect', [
            openidConnectProviderId: GoogleProviderId,
            code                   : 'ya29' +
                                     '.a0AfH6SMCO31EOC1LlE2rnGsFQOkpJNSK95sp7KUb-LXAiqv16YG3Zm_gE7MKA3fZUko1lNpNUnpR8tFfGnvB8m9blDbz4fuvI6oD6LoN9zcuFlzDQtztdpQJmc9fZHnd0FdNlWl34ZizU-JrsT_XvDZTMlDeZ',
        ])

        then:
        verifyResponse(OK, response)
    }

    /*
    [
      {
        "id": "f92b2ec7-6203-49c1-9d1b-972bb87f9420",
        "label": "Google Openid-Connect Provider",
        "openidConnectProviderType": "GOOGLE",
        "authenticationRequestPath": "http://google.com/o/oauth2/v2/auth?scope=openid+email&response_type=code&state=bb0140b9-5e7f-46d2-88bb-d8e66fab66ab&nonce=cda8e9b7
        -ee90-4f95-a3b1-2cd386cda941&client_id=894713962139-bcggqkmpj45gu5v58o5mc9qc89f3tk16.apps.googleusercontent.com"
      },
      {
        "id": "cb33b6f7-8387-439e-91ca-b0662de873d8",
        "label": "Keycloak Openid-Connect Provider",
        "openidConnectProviderType": "KEYCLOAK",
        "authenticationRequestPath": "https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/auth?scope=openid+email&response_type=code&state=1c6771be-7a08
        -423a-8dba-8bc82f833775&nonce=d7d17854-a8d6-404d-9d14-79f65500ec57&client_id=mdm"
      },
      {
        "id": "42d10985-7e02-4276-9268-fbc346255d52",
        "label": "Microsoft Openid-Connect Provider",
        "openidConnectProviderType": "MICROSOFT",
        "authenticationRequestPath": "https://login.microsoftonline.com/organizations/oauth2/v2
        .0/authorize?scope=openid+email&response_type=code&state=58ae9e3c-4c2e-416c-be73-0909d4c1579d&nonce=c0230aff-0427-4e63-bd73-ca7907fbfa9a&client_id=microsoftClientId"
      }
    ]
     */


    Map<String, String> authoriseAgainstKeyCloak(OpenidConnectProvider provider, String username = 'mdm-admin', String password = 'mdm-admin') {

        // Connect and then request the authorise page from KC
        String authoriseEndpoint = "${provider.getFullAuthorizationEndpointUrl()}&redirect_uri=https://jenkins.cs.ox.ac.uk"
        Connection authoriseConnection = Jsoup.connect(authoriseEndpoint)
        Document doc = authoriseConnection.get()

        // Get the login form and complete it
        FormElement form = doc.getElementById('kc-form-login') as FormElement
        form.getElementById('username').val(username)
        form.getElementById('password').val(password)

        // Setup connection to submit form for authentication
        // We MUST submit the cookies from the authorise request along with the authenticate
        Connection connection = form.submit()
            .header('accept', '*/*')
            .cookies(authoriseConnection.response().cookies())

        // Execute and get the response
        // The response "url" will hold all the params we need to pass for token request
        Connection.Response response = connection.execute()

        // Get all the parameters we sent to authorise
        Map<String,String> authorizeParameters = authoriseEndpoint.toURL().query.split('&').collectEntries {it.split('=')}
        // Get all the paraemeters we got back from authenticate
        Map<String,String> authenticateParameters = response.url().query.split('&').collectEntries {it.split('=')}

        // Add them together choosing the authenticate as the preferred value (shouldnt be any difference)
        authorizeParameters.putAll(authenticateParameters)
        authorizeParameters.openidConnectProviderId = keycloakProvider.id.toString()
        authorizeParameters
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
