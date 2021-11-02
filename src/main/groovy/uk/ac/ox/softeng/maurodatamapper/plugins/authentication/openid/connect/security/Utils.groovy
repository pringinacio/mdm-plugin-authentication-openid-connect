package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.security

import uk.ac.ox.softeng.maurodatamapper.security.utils.SecurityUtils

import groovy.util.logging.Slf4j

/**
 * @since 02/11/2021
 */
@Slf4j
class Utils extends SecurityUtils{

   static String generateNonceUuid(String sessionId){
        byte[] securelyRandomBytes = getHash(sessionId)
        String nonce = UUID.nameUUIDFromBytes(securelyRandomBytes).toString()
       log.debug('Generated nonce for {} as {}', sessionId, nonce)
       nonce
    }
}
