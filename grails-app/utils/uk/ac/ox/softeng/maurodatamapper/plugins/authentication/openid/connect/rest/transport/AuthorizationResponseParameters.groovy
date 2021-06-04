package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport

import uk.ac.ox.softeng.maurodatamapper.util.Utils

/**
 * @since 02/06/2021
 */
class AuthorizationResponseParameters {

    UUID openidConnectProviderId
    String sessionState
    String code
    String state
    String redirectUri
    String nonce

    AuthorizationResponseParameters(Map<String, Object> parameters) {
        openidConnectProviderId = Utils.toUuid(parameters.openidConnectProviderId)
        this.sessionState = parameters.session_state
        this.redirectUri = parameters.redirect_uri
        this.code = parameters.code
        this.state = parameters.state
        this.nonce = parameters.nonce
    }
}
