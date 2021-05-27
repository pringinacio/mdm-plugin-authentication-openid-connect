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


import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProvider

import grails.core.GrailsApplication
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.GOOGLE_OPENID_CONNECT_PROVIDER_NAME
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.MICROSOFT_OPENID_CONNECT_PROVIDER_NAME
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.buildAndSaveGoogleProvider
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.buildAndSaveKeycloakProvider
import static uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap.BootstrapModels.buildAndSaveMicrosoftProvider

class BootStrap {

    GrailsApplication grailsApplication

    @Autowired
    MessageSource messageSource

    def init = {servletContext ->

        Map openidConnectConfig = grailsApplication.config.maurodatamapper.openidConnect

        Boolean googleEnabled = openidConnectConfig.google.enabled
        Boolean microsoftEnabled = openidConnectConfig.microsoft.enabled
        Boolean keycloakEnabled = openidConnectConfig.keycloak.enabled

        OpenidConnectProvider.withNewTransaction {

            if (googleEnabled && OpenidConnectProvider.countByLabel(GOOGLE_OPENID_CONNECT_PROVIDER_NAME) == 0) {
                buildAndSaveGoogleProvider(messageSource, openidConnectConfig.google)
            }

            if (microsoftEnabled && OpenidConnectProvider.countByLabel(MICROSOFT_OPENID_CONNECT_PROVIDER_NAME) == 0) {
                buildAndSaveMicrosoftProvider(messageSource, openidConnectConfig.microsoft)
            }

            if (keycloakEnabled && OpenidConnectProvider.countByLabel(KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME) == 0) {
                buildAndSaveKeycloakProvider(messageSource, openidConnectConfig.keycloak)
            }
        }
    }
    def destroy = {
    }
}
