package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import spock.lang.PendingFeature
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.OpenidConnectProviderType
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.test.functional.BaseFunctionalSpec

import grails.core.GrailsApplication
import grails.gorm.transactions.Transactional
import grails.testing.mixin.integration.Integration
import grails.testing.spock.OnceBefore
import groovy.util.logging.Slf4j
import spock.lang.Shared
import spock.lang.Stepwise

import static io.micronaut.http.HttpStatus.NO_CONTENT
import static io.micronaut.http.HttpStatus.OK
import static io.micronaut.http.HttpStatus.UNAUTHORIZED

/**
 * <pre>
 * Controller: authenticating
 * |  POST  | /api/admin/activeSessions  | Action: activeSessionsWithCredentials
 * |  *     | /api/authentication/logout | Action: logout
 * |  POST  | /api/authentication/login  | Action: login
 * </pre>
 * @see uk.ac.ox.softeng.maurodatamapper.security.authentication.AuthenticatingController
 */
@Slf4j
@Integration
@Stepwise
class OpenidConnectAuthenticatingFunctionalSpec extends BaseFunctionalSpec {

    GrailsApplication grailsApplication

    CatalogueUserService catalogueUserService

    OpenidConnectProviderService openidConnectProviderService

    @OnceBefore
    @Transactional
    def checkAndSetupData() {

    }

    @Transactional
    void deleteUser(String id) {
        catalogueUserService.get(id).delete(flush: true)
    }

    String getValidKeycloakProviderId(){
        openidConnectProviderService.findByLabel('Development OpenidConnect Keycloak').id.toString()
    }

    String getValidGoogleProviderId(){
        openidConnectProviderService.findByLabel('Development OpenidConnect Google').id.toString()
    }

    String getValidMicrosoftProviderId(){
        openidConnectProviderService.findByLabel('Development OpenidConnect Microsoft').id.toString()
    }

    @Override
    String getResourcePath() {
        'authentication'
    }

    void 'OCA01 : KEYCLOAK - test logging in with empty authentication code'() {
        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validKeycloakProviderId, accessCode: ''])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA02 : KEYCLOAK - test logging in with random authentication code'() {

        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validKeycloakProviderId, accessCode: UUID.randomUUID().toString()])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA03 : KEYCLOAK - test logging in with no authentication code'() {
        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validKeycloakProviderId])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA05 : GOOGLE - test logging in with empty authentication code'() {
        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validGoogleProviderId, accessCode: ''])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA06 : GOOGLE - test logging in with random authentication code'() {

        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validGoogleProviderId, accessCode: UUID.randomUUID().toString()])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA07 : GOOGLE - test logging in with no authentication code'() {
        when: 'invalid call made to login'
        POST('login', [oauthproviderString: validGoogleProviderId])

        then:
        verifyResponse(UNAUTHORIZED, response)
    }

    void 'OCA08 : GOOGLE - test logging in with valid authentication code'() {
        when: 'invalid call made to login'
        POST('login', [oauthProviderString: validGoogleProviderId, accessCode: 'ya29.a0AfH6SMCO31EOC1LlE2rnGsFQOkpJNSK95sp7KUb-LXAiqv16YG3Zm_gE7MKA3fZUko1lNpNUnpR8tFfGnvB8m9blDbz4fuvI6oD6LoN9zcuFlzDQtztdpQJmc9fZHnd0FdNlWl34ZizU-JrsT_XvDZTMlDeZ', session: activeSessions])

        then:
        verifyResponse(OK, response)
    }


}
