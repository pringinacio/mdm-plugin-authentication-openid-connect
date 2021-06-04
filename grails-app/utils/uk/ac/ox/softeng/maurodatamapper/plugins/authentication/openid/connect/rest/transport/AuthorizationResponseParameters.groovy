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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport

import uk.ac.ox.softeng.maurodatamapper.util.Utils

/**
 * @since 02/06/2021
 */
class AuthorizationResponseParameters {

    UUID openidConnectProviderId
    String sessionState
    String code
    String state
    String redirectUri
    String nonce

    AuthorizationResponseParameters(Map<String, Object> parameters) {
        openidConnectProviderId = Utils.toUuid(parameters.openidConnectProviderId)
        this.sessionState = parameters.session_state
        this.redirectUri = parameters.redirect_uri
        this.code = parameters.code
        this.state = parameters.state
        this.nonce = parameters.nonce
    }
}
