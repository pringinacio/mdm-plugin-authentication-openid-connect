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
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

import grails.gorm.DetachedCriteria
import grails.rest.Resource
import groovy.json.JsonBuilder
import groovy.json.JsonSlurper

@Resource(readOnly = false, formats = ['json', 'xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    OpenidConnectProviderType openidConnectProviderType

    String baseUrl
    String authenticationRequestUrl

    String authenticationRequestParametersJson
    String accessTokenRequestUrl

    String accessTokenRequestParametersJson

    Map<String, Object> authenticationRequestParameters
    Map<String, Object> accessTokenRequestParameters

    static constraints = {
        CallableConstraints.call(CreatorAwareConstraints, delegate)
        label unique: true, blank: false
        baseUrl blank: false
        authenticationRequestUrl blank: false
        accessTokenRequestUrl blank: false
    }

    static mapping = {
        accessTokenRequestParametersJson type: 'text'
        authenticationRequestParametersJson type: 'text'
    }

    static transients = ['accessTokenRequestParameters', 'authenticationRequestParameters']

    OpenidConnectProvider() {
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    def beforeValidate() {
        this.authenticationRequestParametersJson = convertMapParametersToJson(this.authenticationRequestParameters)
        this.accessTokenRequestParametersJson = convertMapParametersToJson(this.accessTokenRequestParameters)
    }

    void setAuthenticationRequestParameters(Map<String, Object> authenticationRequestParameters) {
        this.authenticationRequestParameters = authenticationRequestParameters
        this.authenticationRequestParametersJson = convertMapParametersToJson(authenticationRequestParameters)
    }

    void setAccessTokenRequestParameters(Map<String, Object> accessTokenRequestParameters) {
        this.accessTokenRequestParameters = accessTokenRequestParameters
        this.accessTokenRequestParametersJson = convertMapParametersToJson(accessTokenRequestParameters)
    }

    void setAuthenticationRequestParameters(String authenticationRequestParameters) {
        this.authenticationRequestParametersJson = authenticationRequestParameters
        this.authenticationRequestParameters = convertJsonParametersToMap(authenticationRequestParameters)
    }

    void setAccessTokenRequestParameters(String accessTokenRequestParameters) {
        this.accessTokenRequestParametersJson = accessTokenRequestParameters
        this.accessTokenRequestParameters = convertJsonParametersToMap(accessTokenRequestParameters)
    }

    Map<String, Object> getAuthenticationRequestParameters() {
        authenticationRequestParameters ?: convertJsonParametersToMap(this.authenticationRequestParametersJson)
    }

    Map<String, Object> getAccessTokenRequestParameters() {
        accessTokenRequestParameters ?: convertJsonParametersToMap(this.accessTokenRequestParametersJson)
    }

    static DetachedCriteria<OpenidConnectProvider> by() {
        new DetachedCriteria<OpenidConnectProvider>(OpenidConnectProvider)
    }

    static Map convertJsonParametersToMap(String json) {
        json ? new JsonSlurper().parseText(json) as Map : [:]
    }

    static String convertMapParametersToJson(Map map) {
        map ? new JsonBuilder(map).toString() : ''
    }
}