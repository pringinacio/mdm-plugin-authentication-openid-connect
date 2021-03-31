package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.testing.services.ServiceUnitTest
import spock.lang.Specification
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec

class OpenidConnectAuthenticatingServiceSpec extends BaseUnitSpec implements ServiceUnitTest<OpenidConnectAuthenticatingService>{


    UUID id

    def setup() {

        mockArtefact(OpenidConnectProviderService)

        mockDomains(OpenidConnectProvider)

        OpenidConnectProvider openidConnectProvider1 = new OpenidConnectProvider(
                'Test OpenidConnect Keycloak',
                'mdmAdmin',
                OpenidConnectProviderType.KEYCLOAK,
                grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.baseUrl'),
                "/realms/${grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.realm')}/protocol/openid-connect/auth",
                [
                        client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientid'),
                        response_type: 'code',
                        scope: 'openid email',
                        redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.redirectUri'),
                ],
                "/realms/${grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.realm')}/protocol/openid-connect/token",
                [
                        client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientid'),
                        client_secret: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.clientSecret'),
                        grant_type: "authorization_code",
                        redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.keycloak.redirectUri')

                ]
        )

        checkAndSave(openidConnectProvider1)

        id = openidConnectProvider1.id
    }

    def cleanup() {
    }

}
