/*
 * Copyright 2020 University of Oxford and Health and Social Care Information Centre, also known as NHS Digital
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

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.gorm.mapping.MdmPluginAuthenticationOpenidConnectSchemaMappingContext

import grails.plugins.Plugin

class MdmPluginAuthenticationOpenidConnectGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "4.0.1 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    def title = "Rest Api Plugin"
    // Headline display name of the plugin
    def author = "Christina Alexander"
    def authorEmail = "Christina.Alexander@oxfordcc.co.uk"
    def description = '''\
This plugin implements OpenID Connect integration for Keycloak, Google and Microsoft.
'''

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/rest-api-plugin"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
    //    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
    //    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
    //   def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
    //    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
    //    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

    def dependsOn = [
            mdmCore     : '4.2.0 > *',
            mdmSecurity : '4.2.0 > *'
    ]

    Closure doWithSpring() {
        {->
            mdmPluginAuthenticationOpenidConnectSchemaMappingContext MdmPluginAuthenticationOpenidConnectSchemaMappingContext
        }
    }

    void doWithDynamicMethods() {
    }

    void doWithApplicationContext() {
    }

    void onChange(Map<String, Object> event) {
    }

    void onConfigChange(Map<String, Object> event) {
    }

    void onShutdown(Map<String, Object> event) {
    }
}