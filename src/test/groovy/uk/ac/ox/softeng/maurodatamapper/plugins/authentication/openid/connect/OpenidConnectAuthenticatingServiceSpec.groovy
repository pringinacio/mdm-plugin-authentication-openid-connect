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
                'Development Test Provider 1',
                'mdm-dev',
                OpenidConnectProviderType.GOOGLE,
                "google.com",
                "o/oauth2/v2/auth",
                [
                        client_id: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.clientid'),
                        response_type: 'code&',
                        scope: 'openid email',
                        redirect_uri: grailsApplication.config.getProperty('maurodatamapper.openidConnect.google.redirectUri'),
                        state: "Some State",
                        nonce: UUID.randomUUID().toString()
                ])

        checkAndSave(openidConnectProvider1)

        id = openidConnectProvider1.id
    }

    def cleanup() {
    }

    void "test something"() {
        expect:"fix me"
            true == false
    }
}
