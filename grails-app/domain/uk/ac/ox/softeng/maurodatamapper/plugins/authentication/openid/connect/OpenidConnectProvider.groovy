package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.rest.Resource
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

@Resource(readOnly = false, formats=['json','xml'])
class OpenidConnectProvider implements CreatorAware {

    UUID id
    String label
    OpenidConnectProviderType openidConnectProviderType
    Map parameters
    String baseUrl
    String accessTokenUrl

    static constraints = {
        label unique: true
    }

    OpenidConnectProvider(String label, OpenidConnectProviderType openidConnectProviderType, String url, String accessTokenUrl, Map parameters){
        this.label = label
        this.openidConnectProviderType = openidConnectProviderType
        this.baseUrl = url
        this.parameters = parameters
        this.accessTokenUrl = accessTokenUrl
    }

    @Override
    String getDomainType() {
        OpenidConnectProvider.simpleName
    }

}