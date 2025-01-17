/*
 * Copyright 2020-2022 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
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
package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.gorm.mapping

import uk.ac.ox.softeng.maurodatamapper.core.gorm.mapping.PluginSchemaHibernateMappingContext

import groovy.util.logging.Slf4j

/**
 * Maps all domains in the mdm DataModel plugin into the core schema
 * @since 01/11/2019
 */
@Slf4j
class MdmPluginAuthenticationOpenidConnectSchemaMappingContext extends PluginSchemaHibernateMappingContext {

    @Override
    String getPluginName() {
        'mdmPluginAuthenticationOpenidConnect'
    }

    @Override
    String getSchemaName() {
        'openidconnect'
    }

    @Override
    int getOrder() {
        100 // Make sure loads after security which defaults to 0
    }
}

