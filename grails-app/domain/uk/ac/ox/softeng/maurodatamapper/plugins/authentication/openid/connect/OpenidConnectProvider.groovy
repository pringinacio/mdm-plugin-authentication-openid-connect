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

import grails.rest.Resource
import groovy.json.JsonBuilder
import groovy.json.JsonSlurper
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

@Resource(readOnly = false, formats=['json','xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    String createdBy
    OpenidConnectProviderType openidConnectProviderType

    String baseUrl
    String authenticationRequestUrl
    Map authenticationRequestParameters
    String authenticationRequestParametersJson
    String accessTokenRequestUrl
    Map accessTokenRequestParameters
    String accessTokenRequestParametersJson

    static constraints = {
        label unique: true
    }

    static mapping = {
        accessTokenRequestParametersJson type: 'text'
        authenticationRequestParametersJson type: 'text'
    }

    static transients = ['accessTokenRequestParameters', 'authenticationRequestParameters']

    OpenidConnectProvider(){

    }

    OpenidConnectProvider(String label, String createdBy, OpenidConnectProviderType openidConnectProviderType, String url,
                          String authenticationRequestUrl, Map authenticationRequestParameters,
                          String accessTokenRequestUrl, Map accessTokenRequestParameters){
        this.label = label
        this.createdBy = createdBy
        this.openidConnectProviderType = openidConnectProviderType
        this.baseUrl = url
        this.authenticationRequestUrl = authenticationRequestUrl
        this.authenticationRequestParameters = authenticationRequestParameters
        this.authenticationRequestParametersJson = ''
        this.accessTokenRequestUrl = accessTokenRequestUrl
        this.accessTokenRequestParameters = accessTokenRequestParameters
        this.accessTokenRequestParametersJson = ''


    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    def beforeInsert(){
        this.authenticationRequestParametersJson = new JsonBuilder(this.authenticationRequestParameters).toString()
        this.accessTokenRequestParametersJson = new JsonBuilder(this.accessTokenRequestParameters).toString()
    }

    Map getAccessTokenRequestParameters(){
        if (!accessTokenRequestParameters && accessTokenRequestParametersJson) accessTokenRequestParameters = new JsonSlurper().parseText(accessTokenRequestParametersJson) as Map
        accessTokenRequestParameters
    }

    Map getAuthenticationRequestParameters(){
        if (!authenticationRequestParameters && authenticationRequestParametersJson) authenticationRequestParameters = new JsonSlurper().parseText(authenticationRequestParametersJson) as Map
        authenticationRequestParameters
    }

}