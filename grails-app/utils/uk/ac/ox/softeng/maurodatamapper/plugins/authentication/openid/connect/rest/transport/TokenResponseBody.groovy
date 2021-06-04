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


import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT

/**
 * @since 02/06/2021
 */
class TokenResponseBody {

    String accessToken
    Integer expiresIn
    Integer refreshExpiresIn
    String refreshToken
    String tokenType
    String idToken
    Integer notBeforePolicy
    String sessionState
    String scope

    TokenResponseBody(Map<String, Object> data) {
        accessToken = data.access_token
        expiresIn = data.expires_in as Integer
        refreshExpiresIn = data.refresh_expires_in as Integer
        refreshToken = data.refresh_token
        tokenType = data.token_type
        idToken = data.id_token
        notBeforePolicy = data['not-before-policy'] as Integer
        sessionState = data.session_state
        scope = data.scope
    }

    DecodedJWT getDecodedIdToken(){
        JWT.decode(idToken)
    }
}
