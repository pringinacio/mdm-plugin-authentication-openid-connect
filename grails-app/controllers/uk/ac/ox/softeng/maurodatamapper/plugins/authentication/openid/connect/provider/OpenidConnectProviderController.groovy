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

import uk.ac.ox.softeng.maurodatamapper.core.controller.EditLoggingController
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService

import grails.web.servlet.mvc.GrailsParameterMap

class OpenidConnectProviderController extends EditLoggingController<OpenidConnectProvider> {
    static responseFormats = ['json', 'xml']

    OpenidConnectProviderService openidConnectProviderService

    OpenidConnectProviderController() {
        super(OpenidConnectProvider)
    }

    @Override
    Object index(Integer max) {
        params.max = Math.min(max ?: 10, 100)
        def res = listAllResources(params)
        // The new grails-views code sets the modelAndView object rather than writing the response
        // Therefore if thats written then we dont want to try and re-write it
        if (response.isCommitted() || modelAndView) return
        respond res, [
            view : (params as GrailsParameterMap).boolean('openAccess') ? 'publicIndex': 'index']
    }

    @Override
    void serviceDeleteResource(OpenidConnectProvider resource) {
        openidConnectProviderService.delete(resource)
    }

    @Override
    protected List<OpenidConnectProvider> listAllReadableResources(Map params) {
        params.sort = params.sort ?: 'label'
        openidConnectProviderService.list(params)
    }
}
