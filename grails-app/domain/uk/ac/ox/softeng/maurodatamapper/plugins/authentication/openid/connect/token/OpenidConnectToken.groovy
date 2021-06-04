package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.token

import uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect.provider.OpenidConnectProvider
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.traits.domain.CreatorAware

import com.auth0.jwt.JWT
import com.auth0.jwt.interfaces.DecodedJWT

class OpenidConnectToken implements CreatorAware {

    UUID id
    CatalogueUser catalogueUser
    String idToken
    String accessToken
    String refreshToken
    Long expiresIn
    Long refreshExpiresIn
    OpenidConnectProvider openidConnectProvider

    static constraints = {
        catalogueUser unique: true
        refreshToken blank: false
        idToken blank: false
        refreshToken blank: false
    }

    @Override
    String getDomainType() {
        'OpenidConnectToken'
    }

    DecodedJWT getDecodedIdToken(){
        JWT.decode(idToken)
    }

    DecodedJWT getDecodedRefreshToken(){
        JWT.decode(refreshToken)
    }

    DecodedJWT getDecodedAccessToken(){
        JWT.decode(accessToken)
    }
}
