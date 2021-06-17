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

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocument
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details.DiscoveryDocumentService

import grails.gorm.transactions.Transactional
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.http.uri.UriBuilder

@Transactional
class OpenidConnectProviderService {

    DiscoveryDocumentService discoveryDocumentService

    OpenidConnectProvider get(Serializable id) {
        OpenidConnectProvider.get(id)
    }

    int count() {
        OpenidConnectProvider.count()
    }

    List<OpenidConnectProvider> list(Map pagination) {
        OpenidConnectProvider.by().list(pagination)
    }

    void save(OpenidConnectProvider openidConnectProvider) {
        openidConnectProvider.save(failOnError: true, validate: false)
    }

    void delete(OpenidConnectProvider openidConnectProvider) {
        openidConnectProvider.delete(flush: true)
    }

    OpenidConnectProvider findByLabel(String label) {
        OpenidConnectProvider.findByLabel(label)
    }

    OpenidConnectProvider loadDiscoveryDocumentIntoOpenidConnectProvider(OpenidConnectProvider openidConnectProvider) {
        DiscoveryDocument discoveryDocument = discoveryDocumentService.loadDiscoveryDocumentForOpenidConnectProvider(openidConnectProvider)
        openidConnectProvider.discoveryDocument = discoveryDocument
        openidConnectProvider
    }


    Map<String, Object> loadTokenFromOpenidConnectProvider(OpenidConnectProvider openidConnectProvider, Map<String, String> requestBody) {
        log.debug('Loading token from OC provider')
        URL tokenEndpoint = UriBuilder.of(openidConnectProvider.discoveryDocument.tokenEndpoint).build().toURL()

        HttpClient client = HttpClient.create(getClientHostUrl(tokenEndpoint))
        HttpRequest request = HttpRequest.POST(tokenEndpoint.path, requestBody)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
            .accept(MediaType.APPLICATION_JSON_TYPE)

        loadMapFromEndpoint(client, request)
    }


    Map<String, Object> loadUserInfoFromOpenidConnectProvider(OpenidConnectProvider openidConnectProvider, String accessToken) {
        log.debug('Loading user info from OC provider')
        URL userInfoEndpoint = UriBuilder.of(openidConnectProvider.discoveryDocument.userinfoEndpoint).build().toURL()

        HttpClient client = HttpClient.create(getClientHostUrl(userInfoEndpoint))
        HttpRequest request = HttpRequest.GET(userInfoEndpoint.path)
            .bearerAuth(accessToken)
            .accept(MediaType.APPLICATION_JSON_TYPE)
        loadMapFromEndpoint(client, request)
    }

    private Map<String, Object> loadMapFromEndpoint(HttpClient httpClient, HttpRequest httpRequest) {
        try {
            httpClient.toBlocking().exchange(httpRequest, Argument.mapOf(String, Object)).body()
        } catch (HttpClientResponseException e) {
            switch (e.status) {
                case HttpStatus.UNAUTHORIZED:
                case HttpStatus.FORBIDDEN:
                    return [:]
                default:
                    Map body = e.response.body() as Map<String, Object>
                    body.error ? body : [:]
            }
        }
    }

    private URL getClientHostUrl(URL fullUrl) {
        String clientHostUrl = "${fullUrl.protocol}://${fullUrl.host}"
        if (fullUrl.port != -1) clientHostUrl = "${clientHostUrl}:${fullUrl.port}"
        clientHostUrl.toURL()
    }
}
