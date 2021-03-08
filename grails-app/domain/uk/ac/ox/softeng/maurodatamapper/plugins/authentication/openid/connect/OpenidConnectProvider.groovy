package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.rest.Resource
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

@Resource(readOnly = false, formats=['json','xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    OpenidConnectProviderType providerType
    Map parameters
    String baseUrl
    String accessTokenUrl
    String openidUrl

    static constraints = {
        label unique: true
    }

    OpenidConnectProvider(OpenidConnectProviderType providerType, String url, String accessTokenUrl, String openidUrl, Map parameters){
        this.providerType = providerType
        this.baseUrl = url
        this.parameters = parameters
        this.accessTokenUrl = accessTokenUrl
        this.openidUrl = openidUrl
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

}