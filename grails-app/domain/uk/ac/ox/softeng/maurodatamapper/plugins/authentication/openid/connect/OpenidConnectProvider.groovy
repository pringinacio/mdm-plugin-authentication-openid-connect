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

import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CallableConstraints
import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CreatorAwareConstraints

import grails.rest.Resource
import groovy.json.JsonBuilder
import groovy.json.JsonSlurper
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

@Resource(readOnly = false, formats=['json','xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    OpenidConnectProviderType openidConnectProviderType

    String baseUrl
    String authenticationRequestUrl
    Map authenticationRequestParameters
    String authenticationRequestParametersJson
    String accessTokenRequestUrl
    Map accessTokenRequestParameters
    String accessTokenRequestParametersJson

    static constraints = {
        CallableConstraints.call(CreatorAwareConstraints, delegate)
        label unique: true
    }

    static mapping = {
        accessTokenRequestParametersJson type: 'text'
        authenticationRequestParametersJson type: 'text'
    }

    static transients = ['accessTokenRequestParameters', 'authenticationRequestParameters']

    OpenidConnectProvider(){
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    def beforeValidate(){
        this.authenticationRequestParametersJson = new JsonBuilder(this.authenticationRequestParameters).toString()
        this.accessTokenRequestParametersJson = new JsonBuilder(this.accessTokenRequestParameters).toString()
    }

    Map getAccessTokenRequestParameters(){
        if (!accessTokenRequestParameters && accessTokenRequestParametersJson) accessTokenRequestParameters = new JsonSlurper().parseText(accessTokenRequestParametersJson) as Map
        accessTokenRequestParameters?:[:]
    }

    Map getAuthenticationRequestParameters(){
        if (!authenticationRequestParameters && authenticationRequestParametersJson) authenticationRequestParameters = new JsonSlurper().parseText(authenticationRequestParametersJson) as Map
        authenticationRequestParameters?:[:]
    }

}