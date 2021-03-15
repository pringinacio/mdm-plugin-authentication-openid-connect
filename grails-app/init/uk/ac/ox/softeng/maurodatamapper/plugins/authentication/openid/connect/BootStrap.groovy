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


        OpenidConnectProvider.withNewTransaction {
            if (OpenidConnectProvider.countByLabel('Development OpenidConnect Google') == 0) {
                OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
                        'Development OpenidConnect Google',
                        'mdm-dev',
                        OpenidConnectProviderType.GOOGLE,
                        "google.com",
                        "o/oauth2/v2/auth",
                        [
                                client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.clientid'),
                                response_type: 'code&',
                                scope: 'openid email',
                                redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.redirectUri'),
                                state: "Some State",
                                nonce: UUID.randomUUID().toString()
                        ])
                checkAndSave(messageSource, openidConnectProvider)
            }
        }
    }
    def destroy = {
    }
}
