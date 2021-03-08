package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.web.servlet.mvc.GrailsParameterMap
import uk.ac.ox.softeng.maurodatamapper.core.interceptor.SecurableResourceInterceptor
import uk.ac.ox.softeng.maurodatamapper.security.SecurableResource
import uk.ac.ox.softeng.maurodatamapper.util.Utils


class OpenidConnectProviderInterceptor extends SecurableResourceInterceptor {

    @Override
    def <S extends SecurableResource> Class<S> getSecuredClass() {
        OpenidConnectProvider as Class<S>
    }

    @Override
    void checkIds() {
        Utils.toUuid(params, 'id')
        Utils.toUuid(params, 'openidconnectprovider')
    }

    @Override
    UUID getId() {
        params.id ?: params.openidconnectprovider
    }

    boolean before() {
        if (isIndex() && (params as GrailsParameterMap).boolean('openAccess')) return true
        currentUserSecurityPolicyManager.isApplicationAdministrator() ?: forbiddenDueToNotApplicationAdministrator()
    }
}
