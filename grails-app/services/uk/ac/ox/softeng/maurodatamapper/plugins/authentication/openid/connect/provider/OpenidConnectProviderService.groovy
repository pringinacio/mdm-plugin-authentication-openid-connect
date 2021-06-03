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

    OpenidConnectProvider loadDiscoveryDocumentIntoOpenidConnectProvider(OpenidConnectProvider openidConnectProvider){
        DiscoveryDocument discoveryDocument = discoveryDocumentService.loadDiscoveryDocumentForOpenidConnectProvider(openidConnectProvider)
        openidConnectProvider.discoveryDocument = discoveryDocument
        openidConnectProvider
    }
}
