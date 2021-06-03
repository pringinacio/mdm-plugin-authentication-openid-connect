package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport

import uk.ac.ox.softeng.maurodatamapper.util.Utils

/**
 * @since 02/06/2021
 */
class OpenidConnectAuthenticationDetails {

    UUID openidConnectProvider
    String sessionState
    String code
    String state
    String redirectUri
    String nonce

    void setSession_state(String sessionState){
        this.sessionState = sessionState
    }

    void setRedirect_uri(String redirectUri){
        this.redirectUri = redirectUri
    }

    void setOpenidConnectProvider(String provider){
        this.openidConnectProvider = Utils.toUuid(provider)
    }
}
