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
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.util.logging.Slf4j
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
        OpenidConnectProvider.findByLabel(BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
    }

    @Transactional
    OpenidConnectProvider getGoogleProvider() {
        OpenidConnectProvider.findByLabel(BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
    }

    @Transactional
    OpenidConnectProvider getMicrosoftProvider() {
        OpenidConnectProvider.findByLabel(BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME)
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

    void 'KEYCLOAK01 - test logging in with empty authentication code'() {

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', getResponseBody(keycloakProvider.id.toString(), ''))

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK02 - test logging in with random authentication code'() {

        when: 'in call made to login'
        POST('login?scheme=openIdConnect', getResponseBody(keycloakProvider.id.toString(), UUID.randomUUID().toString()))

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK03 - test logging in with no authentication code'() {
        when: 'in call made to login'
        POST('login?scheme=openIdConnect', getResponseBody(keycloakProvider.id.toString(), null))

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'KEYCLOAK04 - test logging in with  authentication code'() {
        //https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/auth?scope=openid+email&response_type=code&state=1c6771be-7a08-423a-8dba-8bc82f833775&nonce
        // =d7d17854-a8d6-404d-9d14-79f65500ec57&client_id=mdm&redirect_uri=https://jenkins.cs.ox.ac.uk/
        //https://jenkins.cs.ox.ac.uk/?state=1c6771be-7a08-423a-8dba-8bc82f833775&session_state=9d1abb89-2226-4cf0-8077-becc084685b6&code=289a89c2-6072-4d0c-9314
        // -35bd50483b3c.9d1abb89-2226-4cf0-8077-becc084685b6.39967b99-96d6-4dac-89b9-95a9c2770edb
        when: 'in call made to login'
        POST('login?scheme=openIdConnect', getResponseBody(keycloakProvider.id.toString(),
                                                           'd239784b-0ad2-49a2-be91-94f64fd232ce.6b1d3d01-eb2a-43d2-812b-1a2902072f96.39967b99-96d6-4dac-89b9-95a9c2770edb',
                                                           '6b1d3d01-eb2a-43d2-812b-1a2902072f96',
                                                           'd7d17854-a8d6-404d-9d14-79f65500ec57',
                                                           '1c6771be-7a08-423a-8dba-8bc82f833775'))

        then:
        verifyResponse(OK, response)
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
}
