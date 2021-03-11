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
    String openidConnectUrl

    static constraints = {
        label unique: true
    }

    OpenidConnectProvider(String label, OpenidConnectProviderType providerType, String url, String accessTokenUrl, String openidConnectUrl, Map parameters){
        this.providerType = providerType
        this.baseUrl = url
        this.parameters = parameters
        this.accessTokenUrl = accessTokenUrl
        this.openidConnectUrl = openidConnectUrl
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

}