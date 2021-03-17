package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.testing.services.ServiceUnitTest
import spock.lang.Specification
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec

class OpenidConnectProviderServiceSpec extends BaseUnitSpec implements ServiceUnitTest<OpenidConnectProviderService>{

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
        OpenidConnectProvider openidConnectProvider2 = new OpenidConnectProvider(
                'Development Test Provider 2',
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
        OpenidConnectProvider openidConnectProvider3 = new OpenidConnectProvider(
                'Development Test Provider 3',
                'mdm-dev',
                OpenidConnectProviderType.MICROSOFT,
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
        checkAndSave(openidConnectProvider2)
        checkAndSave(openidConnectProvider3)

        id = openidConnectProvider1.id
    }

    void "test get"() {
        expect:
        service.get(id) != null
    }

    void "test list"() {
        when:
        List<OpenidConnectProvider> openidConnectProviderList = service.list(max: 2, orderBy: 'openidConnectProviderType')

        then:
        openidConnectProviderList.size() == 2

        when:
        def ocp1 = openidConnectProviderList[0]
        def ocp2 = openidConnectProviderList[1]

        then:
        ocp1.label == 'Development Test Provider 1'

        and:
        ocp2.label == 'Development Test Provider 2'

    }

    void "test count"() {

        expect:
        service.count() == 3
    }

    void "test delete"() {

        expect:
        service.count() == 3
        OpenidConnectProvider ocp = service.get(id)

        when:
        service.delete(ocp)

        then:
        OpenidConnectProvider.count() == 2
    }

    void "test save"() {

        when:
        OpenidConnectProvider openidConnectProvider = new OpenidConnectProvider(
                'Development Test Provider 4',
                'mdm-dev',
                OpenidConnectProviderType.KEYCLOAK,
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
        service.save(openidConnectProvider)

        then:
        openidConnectProvider.id != null

        when:
        OpenidConnectProvider saved = service.get(openidConnectProvider.id)

        then:
        saved.label == 'Development Test Provider 4'
    }
}
