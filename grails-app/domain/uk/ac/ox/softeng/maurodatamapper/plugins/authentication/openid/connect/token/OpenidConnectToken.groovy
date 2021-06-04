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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT

class OpenidConnectToken implements CreatorAware {

    UUID id
    CatalogueUser catalogueUser
    String idToken
    String accessToken
    String refreshToken
    Long expiresIn
    Long refreshExpiresIn
    OpenidConnectProvider openidConnectProvider

    static constraints = {
        catalogueUser unique: true
        refreshToken blank: false
        idToken blank: false
        refreshToken blank: false
    }

    @Override
    String getDomainType() {
        'OpenidConnectToken'
    }

    DecodedJWT getDecodedIdToken(){
        JWT.decode(idToken)
    }

    DecodedJWT getDecodedRefreshToken(){
        JWT.decode(refreshToken)
    }

    DecodedJWT getDecodedAccessToken(){
        JWT.decode(accessToken)
    }
}
