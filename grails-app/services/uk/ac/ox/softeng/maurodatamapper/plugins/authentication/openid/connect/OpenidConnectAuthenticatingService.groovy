package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.gorm.transactions.Transactional
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInvalidModelException
import uk.ac.ox.softeng.maurodatamapper.core.session.SessionService
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.util.Utils

import io.micronaut.http.client.HttpClient

import javax.servlet.http.HttpSession
import java.net.http.HttpResponse

@Transactional
class OpenidConnectAuthenticatingService {

    OpenidConnectProviderService openidConnectProviderService

    CatalogueUserService catalogueUserService

    SessionService sessionService

    @Transactional
    CatalogueUser authenticateAndObtainUserUsingOauthProvider(HttpSession session, String oauthProviderString, String accessCode){
        log.info('Attempt to access system using OAUTH')

        OpenidConnectProvider openidConnectProviderProvider = openidConnectProviderService.get(Utils.toUuid(oauthProviderString))

        if(!openidConnectProviderProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        CatalogueUser user = null
        HttpSession sessionInfo = sessionService.retrieveSession(session)

        try {
            HttpResponse response = HttpClient
                .create(openidConnectProviderProvider.baseUrl.toURL())
                .toBlocking()
                .exchange(
                        HttpRequest.POST(openidConnectProviderProvider.accessTokenRequestUrl, openidConnectProviderProvider.accessTokenRequestParameters)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                            .accept(MediaType.APPLICATION_JSON_TYPE)
                )

            if (openidConnectProviderProvider.accessTokenRequestParameters["state"] != response.properties["state"]){
                throw new SecurityException('OCAS01:', 'The response state does not match the request state.')
            }

            Map idTokenJson = Base64.decodeBase64(response.body().getAt("id_token"))

            String emailAddress = idTokenJson.get("email")

            user = catalogueUserService.findByEmailAddress(emailAddress)

            if (!user) {
                user = catalogueUserService.createNewUser(  emailAddress: emailAddress,
                                                            password: null,
                                                            createdBy: "openidConnectAuthentication@${openidConnectProviderProvider.baseUrl.toURL().host}",
                                                            pending: false, firstName: "Unknown", lastName: 'Unknown')

                if (!user.validate()) throw new ApiInvalidModelException('OCAS02:', 'Invalid user creation', user.errors)
                user.save(flush: true, validate: false)
                user.addCreatedEdit(user)
            }

        }
        catch (HttpClientResponseException e){
            switch (e.status){
                case HttpStatus.UNAUTHORIZED:
                    return null
                case HttpStatus.BAD_REQUEST:
                    throw new ApiBadRequestException('OCAS02:', 'Could not authenticate against OAUTH Provider due to a bad request')
                default:
                    throw new ApiInternalException('OCAS03:', "Could not authenticate against OAUTH Provider: ${e.getStatus()} ${e.getMessage()}", e)
            }
        }

        user

    }

}
