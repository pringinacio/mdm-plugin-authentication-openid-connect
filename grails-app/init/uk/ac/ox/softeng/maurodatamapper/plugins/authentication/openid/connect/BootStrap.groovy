/*
 * Copyright 2020 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
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

import org.hibernate.id.GUIDGenerator
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType

import grails.core.GrailsApplication
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

class BootStrap {

    GrailsApplication grailsApplication

    @Autowired
    MessageSource messageSource

    def init = {servletContext ->

        Boolean googleEnabled = grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.enabled')
        Boolean microsoftEnabled = grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.enabled')
        Boolean keycloakEnabled = grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.enabled')
        OpenidConnectProvider.withNewTransaction {

            if (googleEnabled && OpenidConnectProvider.countByLabel('Development OpenidConnect Google') == 0) {
                OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
                        'Development OpenidConnect Google',
                        'mdmAdmin',
                        OpenidConnectProviderType.GOOGLE,
                        "google.com",
                        "o/oauth2/v2/auth",
                        [
                                client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.clientid'),
                                response_type: 'code&',
                                scope: 'openid email',
                                redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.redirectUri'),

                        ],
                        "https://oauth2.googleapis.com/token",
                        [
                                cliend_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.clientid'),
                                client_secret: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.clientSecret'),
                                redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.redirectUri'),
                                grant_type: "authorization_code"
                        ])
                checkAndSave(messageSource, openidConnectProvider)
            }

            if (microsoftEnabled && OpenidConnectProvider.countByLabel('Development OpenidConnect Microsoft') == 0) {
                OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
                        'Development OpenidConnect Microsoft',
                        'mdmAdmin',
                        OpenidConnectProviderType.MICROSOFT,
                        "microsoft.com",
                        "o/oauth2/v2/auth",
                        [
                                client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.clientid'),
                                response_type: 'id_token',
                                scope: 'openid',
                                redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.redirectUri')
                        ])
                checkAndSave(messageSource, openidConnectProvider)
            }

            if (keycloakEnabled && OpenidConnectProvider.countByLabel('Development OpenidConnect Keycloak') == 0) {
                OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
                        'Development OpenidConnect Keycloak',
                        'mdmAdmin',
                        OpenidConnectProviderType.KEYCLOAK,
                        grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.baseUrl'),
                        "realms/${grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.realm')}/protocol/openid-connect/auth",
                        [
                                client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.clientid'),
                                response_type: 'id_token',
                                scope: 'openid',
                                redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.microsoft.redirectUri')
                        ],
                        )
                checkAndSave(messageSource, openidConnectProvider)
            }
        }
    }
    def destroy = {
    }
}
