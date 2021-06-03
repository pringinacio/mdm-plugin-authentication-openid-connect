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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.test.FunctionalSpec

import grails.testing.mixin.integration.Integration
import groovy.util.logging.Slf4j
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus

import static io.micronaut.http.HttpStatus.CREATED
import static io.micronaut.http.HttpStatus.NOT_FOUND
import static io.micronaut.http.HttpStatus.NO_CONTENT
import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNPROCESSABLE_ENTITY

/**
 * @since 27/05/2021
 */
@Integration
@Slf4j
class OpenidConnectProviderFunctionalSpec extends FunctionalSpec {

    @Override
    String getResourcePath() {
        'admin/openidConnectProviders'
    }

    Map getValidJson() {
        [label                    : 'Functional Test Provider 4',
         openidConnectProviderType: OpenidConnectProviderType.NON_STANDARD,
         clientId                 : 'testing',
         clientSecret             : 'c2e94d1c',
         discoveryDocument        : [
             issuer               : "http://test.com",
             authorizationEndpoint: "http://test.com/o/oauth2/v2/auth",
             tokenEndpoint        : "http://test.com/o/oauth2/v2/auth",
             jwksUri              : "http://test.com/o/oauth2/v2/auth",
         ]
        ]
    }

    Map getInvalidJson() {
        [label                    : 'Functional Test Provider 4',
         openidConnectProviderType: OpenidConnectProviderType.STANDARD,
        ]
    }

    Map getValidUpdateJson() {
        [clientId         : 'integrationTesting',
         discoveryDocument: [
             userinfoEndpoint: "http://test.com/userinfo",
         ]
        ]
    }

    String getShowJson() {
        '''{
  "id": "${json-unit.matches:id}",
  "lastUpdated": "${json-unit.matches:offsetDateTime}",
  "label": "Functional Test Provider 4",
  "openidConnectProviderType": "NON_STANDARD",
  "clientId": "testing",
  "clientSecret": "c2e94d1c",
  "authorizationEndpointParameters": {
    "id": "${json-unit.matches:id}",
    "lastUpdated": "${json-unit.matches:offsetDateTime}",
    "scope": "openid email",
    "responseType": "code"
  },
  "discoveryDocument": {
    "id": "${json-unit.matches:id}",
    "lastUpdated": "${json-unit.matches:offsetDateTime}",
    "issuer": "http://test.com",
    "authorizationEndpoint": "http://test.com/o/oauth2/v2/auth",
    "tokenEndpoint": "http://test.com/o/oauth2/v2/auth",
    "userinfoEndpoint": null,
    "endSessionEndpoint": null,
    "jwksUri": "http://test.com/o/oauth2/v2/auth"
  }
}'''
    }

    String getAdminIndexJson() {
        '''{
  "count": 3,
  "items": [
    {
      "id": "${json-unit.matches:id}",
      "lastUpdated": "${json-unit.matches:offsetDateTime}",
      "label": "Google Openid-Connect Provider",
      "openidConnectProviderType": "STANDARD"
    },
    {
      "id": "${json-unit.matches:id}",
      "lastUpdated": "${json-unit.matches:offsetDateTime}",
      "label": "Keycloak Openid-Connect Provider",
      "openidConnectProviderType": "STANDARD"
    },
    {
      "id": "${json-unit.matches:id}",
      "lastUpdated": "${json-unit.matches:offsetDateTime}",
      "label": "Microsoft Openid-Connect Provider",
      "openidConnectProviderType": "STANDARD"
    }
  ]
}'''
    }

    /**
     * Items are created by the editor user
     * This ensures that they dont have some possible weird admin protection
     * @return
     */
    String getValidId(Map jsonMap = validJson) {
        loginAdmin()
        POST('', jsonMap)
        verifyResponse CREATED, response
        String id = response.body().id
        logout()
        id
    }

    void removeValidIdObject(String id) {
        removeValidIdObject(id, NO_CONTENT)
    }

    void removeValidIdObject(String id, HttpStatus expectedStatus) {
        if (!id) return
        log.info('Removing valid id {} using DELETE', id)
        loginAdmin()
        DELETE(id)
        verifyResponse expectedStatus, response
        logout()
    }

    void verifySameValidDataCreationResponse() {
        verifyResponse UNPROCESSABLE_ENTITY, response
        assert response.body().total == 1
        assert response.body().errors.first().message
    }

    /*
   * Logged in as admin testing
   * This proves that admin users can mess with items created by other users
   */

    void 'A01 : Test the index action (as admin)'() {
        given:
        loginAdmin()

        when: 'The index action is requested'
        GET('', STRING_ARG)

        then: 'The response is correct'
        verifyJsonResponse(OK, getAdminIndexJson())

    }

    void 'A02 : Test the show action correctly renders an instance (as admin)'() {
        given:
        def id = getValidId()
        loginAdmin()

        when: 'When the show action is called to retrieve a resource'
        GET("$id", STRING_ARG)

        then: 'The response is correct'
        verifyJsonResponse OK, showJson

        cleanup:
        removeValidIdObject(id)
    }

    /*
  * Logged in as admin testing
  * This proves that admin users can mess with items created by other users
  */

    void 'A03 : Test the save action correctly persists an instance (as admin)'() {
        given:
        loginAdmin()

        when:
        POST('', validJson)

        then:
        verifyResponse CREATED, response
        response.body().id

        when: 'Trying to save again using the same info'
        String id1 = response.body().id
        POST('', validJson)

        then:
        verifySameValidDataCreationResponse()
        String id2 = response.body()?.id

        cleanup:
        removeValidIdObject(id1)
        if (id2) {
            removeValidIdObject(id2) // not expecting anything, but just in case
        }
    }

    void 'A04 : Test the delete action correctly deletes an instance (as admin)'() {
        given:
        def id = getValidId()
        loginAdmin()

        when: 'When the delete action is executed on an unknown instance'
        DELETE("${UUID.randomUUID()}")

        then: 'The response is correct'
        verifyResponse NOT_FOUND, response

        when: 'When the delete action is executed on an existing instance'
        DELETE("$id")

        then: 'The response is correct'
        verifyResponse NO_CONTENT, response

        cleanup:
        removeValidIdObject(id, NOT_FOUND)
    }

    /*
   * Logged in as admin testing
   * This proves that admin users can mess with items created by other users
   */

    void 'A05 : Test the update action correctly updates an instance (as admin)'() {
        given:
        def id = getValidId()
        loginAdmin()

        when: 'The update action is called with invalid data'
        PUT("$id", invalidJson)

        then: 'The response is correct'
        verifyResponse UNPROCESSABLE_ENTITY, response

        when: 'The update action is called with valid data'
        PUT("$id", validUpdateJson)

        then: 'The response is correct'
        verifyResponse OK, response
        response.body().id == id
        validUpdateJson.each {k, v ->
            if (v instanceof Map) {
                v.each {k1, v1 ->
                    assert response.body()[k][k1] == v1
                }
            } else {
                assert response.body()[k] == v
            }
        }

        cleanup:
        removeValidIdObject(id)
    }

    void 'EXX : Test editor endpoints are all forbidden'() {
        given:
        def id = getValidId()
        loginEditor()

        when: 'index'
        GET('')

        then:
        verifyForbidden(response)

        when: 'show'
        GET(id)

        then:
        verifyForbidden(response)

        when: 'save'
        POST('', validJson)

        then:
        verifyForbidden(response)

        when: 'update'
        PUT(id, validUpdateJson)

        then:
        verifyForbidden(response)

        when: 'delete'
        DELETE(id)

        then:
        verifyForbidden(response)

        cleanup:
        removeValidIdObject(id)
    }

    void 'LXX : Test not logged endpoints are all forbidden'() {
        given:
        def id = getValidId()

        when: 'index'
        GET('')

        then:
        verifyForbidden(response)

        when: 'show'
        GET(id)

        then:
        verifyForbidden(response)

        when: 'save'
        POST('', validJson)

        then:
        verifyForbidden(response)

        when: 'update'
        PUT(id, validUpdateJson)

        then:
        verifyForbidden(response)

        when: 'delete'
        DELETE(id)

        then:
        verifyForbidden(response)

        cleanup:
        removeValidIdObject(id)
    }

    void 'NXX : Test logged in/authenticated endpoints are all forbidden'() {
        given:
        def id = getValidId()
        loginAuthenticated()

        when: 'index'
        GET('')

        then:
        verifyForbidden(response)

        when: 'show'
        GET(id)

        then:
        verifyForbidden(response)

        when: 'save'
        POST('', validJson)

        then:
        verifyForbidden(response)

        when: 'update'
        PUT(id, validUpdateJson)

        then:
        verifyForbidden(response)

        when: 'delete'
        DELETE(id)

        then:
        verifyForbidden(response)

        cleanup:
        removeValidIdObject(id)
    }

    void 'RXX : Test reader endpoints are all forbidden'() {
        given:
        def id = getValidId()
        loginReader()

        when: 'index'
        GET('')

        then:
        verifyForbidden(response)

        when: 'show'
        GET(id)

        then:
        verifyForbidden(response)

        when: 'save'
        POST('', validJson)

        then:
        verifyForbidden(response)

        when: 'update'
        PUT(id, validUpdateJson)

        then:
        verifyForbidden(response)

        when: 'delete'
        DELETE(id)

        then:
        verifyForbidden(response)

        cleanup:
        removeValidIdObject(id)
    }


    def 'check public endpoint'() {
        when: 'not logged in'
        HttpResponse<List<Map>> localResponse = GET('openidConnectProviders', Argument.listOf(Map), true)

        then:
        verifyPublicResponse(localResponse)

        when: 'reader'
        loginReader()
        localResponse = GET('openidConnectProviders', Argument.listOf(Map), true)

        then:
        verifyPublicResponse(localResponse)

        when: 'authenticated'
        loginAuthenticated()
        localResponse = GET('openidConnectProviders', Argument.listOf(Map), true)

        then:
        verifyPublicResponse(localResponse)

        when: 'editor'
        loginEditor()
        localResponse = GET('openidConnectProviders', Argument.listOf(Map), true)

        then:
        verifyPublicResponse(localResponse)
    }

    void verifyPublicResponse(HttpResponse<List<Map>> localResponse) {
        verifyResponse(OK, localResponse)

        Map<String, String> google = localResponse.body().find {it.label == BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME}
        Map<String, String> microsoft = localResponse.body().find {it.label == BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME}
        Map<String, String> keycloak = localResponse.body().find {it.label == BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME}

        assert google
        assert microsoft
        assert keycloak

        assert google.id
        assert google.openidConnectProviderType == 'STANDARD'
        String authorizationEndpoint = google.authorizationEndpoint
        log.info('Google: {}', authorizationEndpoint)
        assert authorizationEndpoint
        assert authorizationEndpoint.startsWith('https://accounts.google.com/o/oauth2/v2/auth?')
        assert authorizationEndpoint.contains('response_type=code')
        assert authorizationEndpoint.contains('client_id=894713962139-bcggqkmpj45gu5v58o5mc9qc89f3tk16.apps.googleusercontent.com')
        assert authorizationEndpoint.contains('scope=openid+email')
        assert authorizationEndpoint.find(/state=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)
        assert authorizationEndpoint.find(/nonce=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)

        assert microsoft.id
        assert microsoft.openidConnectProviderType == 'STANDARD'
        authorizationEndpoint = microsoft.authorizationEndpoint
        log.info('Microsoft: {}', authorizationEndpoint)
        assert authorizationEndpoint
        assert authorizationEndpoint.startsWith('https://login.microsoftonline.com/common/oauth2/authorize?')
        assert authorizationEndpoint.contains('response_type=code')
        assert authorizationEndpoint.contains('client_id=microsoftClientId')
        assert authorizationEndpoint.contains('scope=openid+email')
        assert authorizationEndpoint.find(/state=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)
        assert authorizationEndpoint.find(/nonce=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)

        assert keycloak.id
        assert keycloak.openidConnectProviderType == 'STANDARD'
        authorizationEndpoint = keycloak.authorizationEndpoint
        log.info('Keycloak: {}', authorizationEndpoint)
        assert authorizationEndpoint
        assert authorizationEndpoint.startsWith('https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/auth?')
        assert authorizationEndpoint.contains('response_type=code')
        assert authorizationEndpoint.contains('client_id=mdm')
        assert authorizationEndpoint.contains('scope=openid+email')
        assert authorizationEndpoint.find(/state=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)
        assert authorizationEndpoint.find(/nonce=[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/)
    }
}
