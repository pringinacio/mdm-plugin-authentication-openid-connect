package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.details

import uk.ac.ox.softeng.maurodatamapper.test.integration.BaseIntegrationSpec

import grails.gorm.transactions.Rollback
import grails.testing.mixin.integration.Integration
import groovy.util.logging.Slf4j

/**
 * @since 02/06/2021
 */
@Integration
@Slf4j
@Rollback
class DiscoveryDocumentServiceSpec extends BaseIntegrationSpec {

    DiscoveryDocumentService discoveryDocumentService

    void 'test get keycloak discovery document'(){
        when:
        Map<String, Object> dd = discoveryDocumentService.loadDiscoveryDocumentMapFromUrl('https://jenkins.cs.ox.ac.uk/auth/realms/test/.well-known/openid-configuration')

        then:
        dd
        dd.size() == 29
        dd.issuer == 'https://jenkins.cs.ox.ac.uk/auth/realms/test'
        dd.authorization_endpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/auth'
        dd.token_endpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/token'
        dd.userinfo_endpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/userinfo'
        dd.end_session_endpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/logout'
        dd.jwks_uri == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/certs'
    }

    void 'test get microsoft discovery document'(){
        when:
        Map<String, Object> dd = discoveryDocumentService.loadDiscoveryDocumentMapFromUrl('https://login.microsoftonline.com/common/.well-known/openid-configuration')

        then:
        dd
        dd.size() == 23
        dd.issuer == 'https://sts.windows.net/{tenantid}/'
        dd.authorization_endpoint == 'https://login.microsoftonline.com/common/oauth2/authorize'
        dd.token_endpoint == 'https://login.microsoftonline.com/common/oauth2/token'
        dd.userinfo_endpoint == 'https://login.microsoftonline.com/common/openid/userinfo'
        dd.end_session_endpoint == 'https://login.microsoftonline.com/common/oauth2/logout'
        dd.jwks_uri == 'https://login.microsoftonline.com/common/discovery/keys'
    }

    void 'test get google discovery document'(){
        when:
        Map<String, Object> dd = discoveryDocumentService.loadDiscoveryDocumentMapFromUrl('https://accounts.google.com/.well-known/openid-configuration')

        then:
        dd
        dd.size() == 15
        dd.issuer == 'https://accounts.google.com'
        dd.authorization_endpoint == 'https://accounts.google.com/o/oauth2/v2/auth'
        dd.token_endpoint == 'https://oauth2.googleapis.com/token'
        dd.userinfo_endpoint == 'https://openidconnect.googleapis.com/v1/userinfo'
        !dd.end_session_endpoint
        dd.jwks_uri == 'https://www.googleapis.com/oauth2/v3/certs'
    }


    void 'test create discovery document'(){
        given:
        Map<String, Object> dd = discoveryDocumentService.loadDiscoveryDocumentMapFromUrl('https://jenkins.cs.ox.ac.uk/auth/realms/test/.well-known/openid-configuration')

        when:
        DiscoveryDocument document = discoveryDocumentService.createDiscoveryDocument(dd)

        then:
        document.issuer == 'https://jenkins.cs.ox.ac.uk/auth/realms/test'
        document.authorizationEndpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/auth'
        document.tokenEndpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/token'
        document.userinfoEndpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/userinfo'
        document.endSessionEndpoint == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/logout'
        document.jwksUri == 'https://jenkins.cs.ox.ac.uk/auth/realms/test/protocol/openid-connect/certs'
    }

    @Override
    void setupDomainData() {

    }
}
