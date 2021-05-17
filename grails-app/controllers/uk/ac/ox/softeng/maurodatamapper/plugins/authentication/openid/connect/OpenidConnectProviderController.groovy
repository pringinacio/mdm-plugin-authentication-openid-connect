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


import org.springframework.beans.factory.annotation.Autowired
import uk.ac.ox.softeng.maurodatamapper.core.container.Classifier
import uk.ac.ox.softeng.maurodatamapper.core.controller.EditLoggingController
import uk.ac.ox.softeng.maurodatamapper.security.SecurityPolicyManagerService

class OpenidConnectProviderController extends EditLoggingController<OpenidConnectProvider>{
	static responseFormats = ['json', 'xml']

    @Autowired(required=false)
    SecurityPolicyManagerService securityPolicyManagerService

    OpenidConnectProviderService openidConnectProviderService

    OpenidConnectProviderController(){
        super(OpenidConnectProvider)
    }


    @Override
    protected OpenidConnectProvider saveResource(OpenidConnectProvider resource){
        OpenidConnectProvider oauthProvider = super.saveResource(resource) as OpenidConnectProvider

        if (securityPolicyManagerService){
            currentUserSecurityPolicyManager = securityPolicyManagerService.addSecurityForSecurableResource(resource, currentUser, resource.label)
        }

        oauthProvider
    }

    @Override
    void serviceDeleteResource(OpenidConnectProvider resource){
        openidConnectProviderService.delete(resource)
    }

    @Override
    protected List<OpenidConnectProvider> listAllReadableResources(Map params) {
        params.sort = params.sort ?: 'label'
        openidConnectProviderService.list(params)
    }
}
