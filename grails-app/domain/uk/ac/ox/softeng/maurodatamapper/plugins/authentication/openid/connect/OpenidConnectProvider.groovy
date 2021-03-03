package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.rest.Resource

@Resource(readOnly = false, formats=['json','xml'])
class OpenidConnectProvider {

    String label;
    OpenidConnectProviderType providerType;
    Map parameters;
    String baseUrl;
    String supplementalUrl;
    String openidUrl;
    String userIdentifierKey;
    String userInformationUrl;

    static constraints = {
        label unique: true
    }

    OpenidConnectProvider(OpenidConnectProviderType providerType, String url, Map parameters){
        this.providerType = providerType
        this.url = url
        this.parameters = parameters
    }
}