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
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec

import grails.testing.services.ServiceUnitTest

class OpenidConnectProviderServiceSpec extends BaseUnitSpec implements ServiceUnitTest<OpenidConnectProviderService> {

    UUID id

    def setup() {
        mockArtefact(OpenidConnectProviderService)
        mockDomains(OpenidConnectProvider)

        id = BootstrapModels.buildAndSaveGoogleProvider(messageSource, grailsApplication.config.maurodatamapper.openidConnect.google).id
        BootstrapModels.buildAndSaveMicrosoftProvider(messageSource, grailsApplication.config.maurodatamapper.openidConnect.microsoft)
        BootstrapModels.buildAndSaveKeycloakProvider(messageSource, grailsApplication.config.maurodatamapper.openidConnect.keycloak)
    }

    void "test get"() {
        expect:
        service.get(id) != null
    }

    void "test list"() {
        when:
        List<OpenidConnectProvider> openidConnectProviderList = service.list(max: 2, orderBy: 'openidConnectProviderType')

        then:
        openidConnectProviderList.size() == 2

        when:
        def ocp1 = openidConnectProviderList[0]
        def ocp2 = openidConnectProviderList[1]

        then:
        ocp1.label == BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME

        and:
        ocp2.label == BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME

    }

    void "test count"() {

        expect:
        service.count() == 3
    }

    void "test delete"() {

        expect:
        service.count() == 3
        OpenidConnectProvider ocp = service.get(id)

        when:
        service.delete(ocp)

        then:
        OpenidConnectProvider.count() == 2
    }

    void "test save"() {

        when:
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: 'Development Test Provider 4',
            createdBy: StandardEmailAddress.UNIT_TEST,
            openidConnectProviderType: OpenidConnectProviderType.KEYCLOAK,
            baseUrl: "http://google.com",
            authenticationRequestUrl: "o/oauth2/v2/auth",
            authenticationRequestParameters: [
                client_id    : grailsApplication.config.maurodatamapper.openidConnect.google.clientid,
                response_type: 'code&',
                scope        : 'openid email',
                redirect_uri : grailsApplication.config.maurodatamapper.openidConnect.google.redirectUri,
                state        : "Some State",
                nonce        : UUID.randomUUID().toString()
            ]
        )
        service.save(openidConnectProvider)

        then:
        openidConnectProvider.id != null

        when:
        OpenidConnectProvider saved = service.get(openidConnectProvider.id)

        then:
        saved.label == 'Development Test Provider 4'
    }
}
