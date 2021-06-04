package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token

import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.jwt.OpenidConnectIdTokenJwtVerifier
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProviderService
import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.rest.transport.TokenResponseBody
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser

import com.auth0.jwt.exceptions.JWTVerificationException
import grails.gorm.transactions.Transactional

@Transactional
class OpenidConnectTokenService {

    OpenidConnectProviderService openidConnectProviderService

    void delete(OpenidConnectToken openidConnectToken) {
        openidConnectToken.delete(flush: true)
    }

    OpenidConnectToken findByCatalogueUser(CatalogueUser catalogueUser) {
        OpenidConnectToken.findByCatalogueUser(catalogueUser)
    }

    void updateAndStoreTokenForCatalogueUser(CatalogueUser catalogueUser, TokenResponseBody tokenResponseBody) {

        OpenidConnectToken existingToken = findByCatalogueUser(catalogueUser)
        if (existingToken) delete(existingToken)

        OpenidConnectToken token = new OpenidConnectToken(
            catalogueUser: catalogueUser,
            refreshToken: tokenResponseBody.refreshToken,
            idToken: tokenResponseBody.idToken,
            accessToken: tokenResponseBody.accessToken,
            expiresIn: tokenResponseBody.expiresIn,
            refreshExpiresIn: tokenResponseBody.refreshExpiresIn
        )
        if (!token.validate()) {
            throw new ApiInvalidModelException('OCTSS01', 'Could not update and store openid connect token', token.errors)
        }
        token.save(validate: false, flush: true)
    }

    boolean verifyIdTokenForUser(CatalogueUser catalogueUser) {
        OpenidConnectToken token = findByCatalogueUser(catalogueUser)
        OpenidConnectIdTokenJwtVerifier verifier = new OpenidConnectIdTokenJwtVerifier(token.openidConnectProvider, token.decodedIdToken, null, null, null)

        try {
            verifier.verify()
        } catch (JWTVerificationException exception) {
            log.warn("Access token failed verification: ${exception.message}")
            false
        }
        true
    }

    void refreshToken() {
        /*
        grant_type : "refresh_token"
        client_id
        client_secret
        refresh_token : the refresh token from the original request

        same process as loadToken but using these in the body
         */

    }
}
