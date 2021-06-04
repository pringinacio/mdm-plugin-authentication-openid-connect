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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.parameters

import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CallableConstraints
import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CreatorAwareConstraints
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.parameters.Display
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.parameters.Prompt
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware


/**
 * See <a href=https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint>OpenId Connect Specification</a>
 */
class AuthorizationEndpointParameters implements CreatorAware {

    UUID id
    // Space separated list
    String scope
    // Should always be 'code'
    String responseType

    String responseMode
    Display display
    Prompt prompt
    Long maxAge
    // Space separated list
    String uiLocales
    String idTokenHint
    String loginHint
    // Space separated list
    String acrValues

    // Should never be set by a user, this should be generated by the service
    //    String nonce
    // Should be added by the UI to redirect back to the correct page
    //    String redirectUri
    // Used across all requests therefore store in the provider
    //    String clientId

    static constraints = {
        CallableConstraints.call(CreatorAwareConstraints, delegate)
        scope blank: false
        responseType blank: false
        responseMode blank: false, nullable: true
        //        nonce blank: false, nullable: true
        uiLocales blank: false, nullable: true
        idTokenHint blank: false, nullable: true
        loginHint blank: false, nullable: true
        acrValues blank: false, nullable: true
        display nullable: true
        prompt nullable: true
        maxAge min: 0L, nullable: true
    }

    static belongsTo = [openidConnectProvider: OpenidConnectProvider]

    AuthorizationEndpointParameters() {
        scope = 'openid email'
        responseType = 'code'
    }

    @Override
    String getDomainType() {
        AuthorizationEndpointParameters.simpleName
    }

    String getClientId() {
        openidConnectProvider?.clientId
    }

    Map<String, String> getAsMap() {
        [scope        : scope,
         response_type: responseType,
         client_id    : clientId,
         response_mode: responseMode,
         display      : display?.toString()?.toLowerCase(),
         prompt       : prompt?.toString()?.toLowerCase(),
         max_age      : maxAge == null ? '' : maxAge.toString(),
         ui_locales   : uiLocales,
         id_token_hint: idTokenHint,
         login_hint   : loginHint,
         acr_values   : acrValues,
         state        : UUID.randomUUID().toString(),
         nonce        : UUID.randomUUID().toString()
        ].findAll {k, v -> v}
    }
}
