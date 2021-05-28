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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType

import groovy.util.logging.Slf4j
import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

/**
 * @since 27/05/2021
 */
@Slf4j
class BootstrapModels {

    public static final String GOOGLE_OPENID_CONNECT_PROVIDER_NAME = 'Google Openid-Connect Provider'
    public static final String MICROSOFT_OPENID_CONNECT_PROVIDER_NAME = 'Microsoft Openid-Connect Provider'
    public static final String KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME = 'Keycloak Openid-Connect Provider'

    static OpenidConnectProvider buildAndSaveGoogleProvider(MessageSource messageSource, Map openidConnectConfig) {
        log.info('Adding {}', GOOGLE_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: GOOGLE_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.GOOGLE,
            baseUrl: "http://google.com",
            authenticationRequestUrl: "o/oauth2/v2/auth",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,

            ],
            accessTokenRequestUrl: "https://oauth2.googleapis.com/token",
            accessTokenRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                redirect_uri : openidConnectConfig.redirectUri,
                grant_type   : "authorization_code"
            ])
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveMicrosoftProvider(MessageSource messageSource, Map openidConnectConfig) {
        log.info('Adding {}', MICROSOFT_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: MICROSOFT_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.MICROSOFT,
            baseUrl: "https://login.microsoftonline.com",
            authenticationRequestUrl: "${openidConnectConfig.tenant}/oauth2/v2.0/authorize",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,
            ],
            accessTokenRequestUrl: "${openidConnectConfig.tenant}/oauth2/v2.0/token",
            accessTokenRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                grant_type   : "authorization_code",
                redirect_uri : openidConnectConfig.redirectUri

            ]
        )
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveKeycloakProvider(MessageSource messageSource, Map openidConnectConfig) {
        log.info('Adding {}', KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME)
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.KEYCLOAK,
            baseUrl: openidConnectConfig.baseUrl,
            authenticationRequestUrl: "/realms/${openidConnectConfig.realm}/protocol/openid-connect/auth",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,
            ],
            accessTokenRequestUrl: "/realms/${openidConnectConfig.realm}/protocol/openid-connect/token",
            accessTokenRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                grant_type   : "authorization_code",
                redirect_uri : openidConnectConfig.redirectUri

            ]
        )
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }
}
