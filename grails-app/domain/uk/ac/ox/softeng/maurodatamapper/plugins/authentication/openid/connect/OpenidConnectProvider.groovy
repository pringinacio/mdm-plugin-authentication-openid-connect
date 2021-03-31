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