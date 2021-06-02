package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

class DiscoveryDocument implements CreatorAware{

    UUID id
    String issuer
    String authorizationEndpoint
    String tokenEndpoint
    String userinfoEndpoint
    String endSessionEndpoint
    String jwksUri

    static belongsTo = [
        openidConnectProvider: OpenidConnectProvider
    ]

    static constraints = {
        issuer blank: false, url: true
        authorizationEndpoint blank: false, url: true
        tokenEndpoint blank: false, url: true
        userinfoEndpoint blank: false, url: true
        endSessionEndpoint blank: false, url: true, nullable: true
        jwksUri blank: false, url: true
    }

    @Override
    String getDomainType() {
        DiscoveryDocument.simpleName
    }
}
