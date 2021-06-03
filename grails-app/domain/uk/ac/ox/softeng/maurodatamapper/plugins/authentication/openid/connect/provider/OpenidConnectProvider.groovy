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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider

import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CallableConstraints
import uk.ac.ox.softeng.maurodatamapper.gorm.constraint.callable.CreatorAwareConstraints
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocument
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.parameters.AuthenticationRequestParameters
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

import grails.gorm.DetachedCriteria
import grails.rest.Resource
import io.micronaut.http.uri.UriBuilder

@Resource(readOnly = false, formats = ['json', 'xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    OpenidConnectProviderType openidConnectProviderType

    String discoveryDocumentUrl

    String clientId
    String clientSecret

    AuthenticationRequestParameters authenticationRequestParameters
    DiscoveryDocument discoveryDocument

    static constraints = {
        CallableConstraints.call(CreatorAwareConstraints, delegate)
        label unique: true, blank: false
        discoveryDocumentUrl blank: false, url: true, nullable: true
        clientId blank: false
        clientSecret blank: false
        discoveryDocument nullable: true
    }

    static mapping = {
    }

    OpenidConnectProvider() {
        authenticationRequestParameters = new AuthenticationRequestParameters()
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    def beforeValidate() {
        authenticationRequestParameters?.openidConnectProvider = this
        authenticationRequestParameters?.createdBy = this.createdBy
        discoveryDocument?.openidConnectProvider = this
        discoveryDocument?.createdBy = this.createdBy
    }

    Map<String, Object> getAccessTokenRequestParameters(String code) {
        [grant_type   : 'authorization_code',
         client_id    : clientId,
         client_secret: clientSecret,
         code         : code]
    }

    String getFullAuthenticationEndpointUrl() {
        UriBuilder builder = UriBuilder.of(discoveryDocument.authorizationEndpoint)
        authenticationRequestParameters.getAsMap().each {k, v ->
            builder = builder.queryParam(k, v)
        }
        builder.build().toString()
    }

    static DetachedCriteria<OpenidConnectProvider> by() {
        new DetachedCriteria<OpenidConnectProvider>(OpenidConnectProvider)
    }
}