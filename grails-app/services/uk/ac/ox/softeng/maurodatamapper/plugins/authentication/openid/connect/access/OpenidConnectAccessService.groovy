package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.access

import groovy.util.logging.Slf4j

import javax.servlet.ServletContext
import javax.servlet.http.HttpSession
import javax.servlet.http.HttpSessionEvent
import javax.servlet.http.HttpSessionListener

/**
 * @since 15/06/2021
 */
@Slf4j
class OpenidConnectAccessService implements HttpSessionListener{

    static final String ACCESS_EXPIRY_SESSION_ATTRIBUTE_NAME='openidAccessExpiry'
    static final String REFRESH_EXPIRY_SESSION_ATTRIBUTE_NAME='openidRefreshExpiry'
    static final String OPEN_ID_AUTHENTICATION_SESSION_ATTRIBUTE_NAME='openidAuthentication'

    /**
     * Destruction of the session should result in us revoking any access tokens
     * @param se
     */
    @Override
    void sessionDestroyed(HttpSessionEvent se) {
        if(se.session.getAttribute())
        log.info('Session destroyed')
    }
}
