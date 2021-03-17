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
    Map parameters
    String parametersJson
    String baseUrl
    String accessTokenUrl

    static constraints = {
        label unique: true
    }

    static mapping = {
        parametersJson type: 'text'
    }

    static transients = ['parameters']

    OpenidConnectProvider(String label, String createdBy, OpenidConnectProviderType openidConnectProviderType, String url, String accessTokenUrl, Map parameters){
        this.label = label
        this.createdBy = createdBy
        this.openidConnectProviderType = openidConnectProviderType
        this.baseUrl = url
        this.parameters = parameters
        this.parametersJson = ''
        this.accessTokenUrl = accessTokenUrl
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

    def beforeInsert(){
        this.parametersJson = new JsonBuilder(this.parameters).toString()
    }

    Map getParameters(){
        if (!parameters && parametersJson) parameters = new JsonSlurper().parseText(this.parametersJson) as Map
        parameters
    }

}