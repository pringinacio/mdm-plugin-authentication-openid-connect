package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.bootstrap

import uk.ac.ox.softeng.maurodatamapper.core.bootstrap.StandardEmailAddress
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType

import org.springframework.context.MessageSource

import static uk.ac.ox.softeng.maurodatamapper.util.GormUtils.checkAndSave

/**
 * @since 27/05/2021
 */
class BootstrapModels {

    public static final String GOOGLE_OPENID_CONNECT_PROVIDER_NAME = 'Google Openid-Connect Provider'
    public static final String MICROSOFT_OPENID_CONNECT_PROVIDER_NAME = 'Microsoft Openid-Connect Provider'
    public static final String KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME = 'Keycloak Openid-Connect Provider'

    static OpenidConnectProvider buildAndSaveGoogleProvider(MessageSource messageSource, Map openidConnectConfig) {
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: GOOGLE_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.GOOGLE,
            baseUrl: "http://google.com",
            authenticationRequestUrl: "o/oauth2/v2/auth",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,

            ],
            accessTokenRequestUrl: "https://oauth2.googleapis.com/token",
            accessTokenRequestParameters: [
                cliend_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                redirect_uri : openidConnectConfig.redirectUri,
                grant_type   : "authorization_code"
            ])
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveMicrosoftProvider(MessageSource messageSource, Map openidConnectConfig) {
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: MICROSOFT_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.MICROSOFT,
            baseUrl: "https://login.microsoftonline.com",
            authenticationRequestUrl: "${openidConnectConfig.tenant}/oauth2/v2.0/authorize",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,
            ],
            accessTokenRequestUrl: "${openidConnectConfig.tenant}/oauth2/v2.0/token",
            accessTokenRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                grant_type   : "authorization_code",
                redirect_uri : openidConnectConfig.redirectUri

            ]
        )
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }

    static OpenidConnectProvider buildAndSaveKeycloakProvider(MessageSource messageSource, Map openidConnectConfig) {
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
            label: KEYCLOAK_OPENID_CONNECT_PROVIDER_NAME,
            createdBy: StandardEmailAddress.ADMIN,
            openidConnectProviderType: OpenidConnectProviderType.KEYCLOAK,
            baseUrl: openidConnectConfig.baseUrl,
            authenticationRequestUrl: "/realms/${openidConnectConfig.realm}/protocol/openid-connect/auth",
            authenticationRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                response_type: 'code',
                scope        : 'openid email',
                redirect_uri : openidConnectConfig.redirectUri,
            ],
            accessTokenRequestUrl: "/realms/${openidConnectConfig.realm}/protocol/openid-connect/token",
            accessTokenRequestParameters: [
                client_id    : openidConnectConfig.clientid,
                client_secret: openidConnectConfig.clientSecret,
                grant_type   : "authorization_code",
                redirect_uri : openidConnectConfig.redirectUri

            ]
        )
        checkAndSave(messageSource, openidConnectProvider)
        openidConnectProvider
    }
}
