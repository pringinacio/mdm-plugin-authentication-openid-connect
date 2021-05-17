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

import grails.testing.services.ServiceUnitTest
import spock.lang.Specification
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec

class OpenidConnectAuthenticatingServiceSpec extends BaseUnitSpec implements ServiceUnitTest<OpenidConnectAuthenticatingService>{


    UUID id

    def setup() {

        mockArtefact(OpenidConnectProviderService)

        mockDomains(OpenidConnectProvider)

        OpenidConnectProvider openidConnectProvider1 = new OpenidConnectProvider(
                'Test OpenidConnect Keycloak',
                'mdmAdmin',
                OpenidConnectProviderType.KEYCLOAK,
                grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.baseUrl'),
                "/realms/${grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.realm')}/protocol/openid-connect/auth",
                [
                        client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientid'),
                        response_type: 'code',
                        scope: 'openid email',
                        redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.redirectUri'),
                ],
                "/realms/${grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.realm')}/protocol/openid-connect/token",
                [
                        client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientid'),
                        client_secret: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientSecret'),
                        grant_type: "authorization_code",
                        redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.redirectUri')

                ]
        )

        checkAndSave(openidConnectProvider1)

        id = openidConnectProvider1.id
    }

    def cleanup() {
    }

}
