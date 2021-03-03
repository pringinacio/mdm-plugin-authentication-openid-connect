package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.UserSecurityPolicyManager
import uk.ac.ox.softeng.maurodatamapper.security.UserSecurityPolicyManagerInterceptor
import uk.ac.ox.softeng.maurodatamapper.security.interceptor.SecurityPolicyManagerInterceptor


class OpenidConnectProviderInterceptor implements SecurityPolicyManagerInterceptor{

    public static final String OAUTH_PROVIDER_HEADER = 'oauthProvider'

    SessionService sessionService
    OpenidConnectProviderService openidConnectProviderService

    OpenidConnectProviderInterceptor(){
        match(uri: '/**/api/**/')
        .excludes(controller: 'authenticating', action: 'login')
        .excludes(controller: 'authenticating', action: 'logout')

        order = UserSecurityPolicyManagerInterceptor.ORDER - 100
    }


    boolean before() {
        checkSessionIsValid()

        if (!securityPolicyManagerIsSet()){
            String oauthProviderHeader = request.getHeader(OAUTH_PROVIDER_HEADER)

            CatalogueUser authenticatedUser = openidConnectProviderService.authenticateAndObtainUserUsingOauthProvider(oauthProviderHeader)

            if (!authenticatedUser)
                return true

            UserSecurityPolicyManager userSecurityPolicyManager = openidConnectProviderService.retrieveOrBuildUserSecurityPolicyManager(authenticatedUser, session)

            setCurrentUserSecurityPolicyManager(userSecurityPolicyManager)
        }

        true
    }

    boolean after() { true }

    void afterView() {
        // no-op
    }
}
