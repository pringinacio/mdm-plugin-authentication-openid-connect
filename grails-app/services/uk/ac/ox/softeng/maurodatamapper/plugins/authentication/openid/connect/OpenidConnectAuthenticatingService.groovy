package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.gorm.transactions.Transactional
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.client.exceptions.HttpClientResponseException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiBadRequestException
import uk.ac.ox.softeng.maurodatamapper.api.exception.ApiInternalException
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUser
import uk.ac.ox.softeng.maurodatamapper.security.CatalogueUserService
import uk.ac.ox.softeng.maurodatamapper.util.Utils

import io.micronaut.http.client.HttpClient

import java.net.http.HttpResponse

@Transactional
class OpenidConnectAuthenticatingService {

    OpenidConnectProviderService openidConnectProviderService

    CatalogueUserService catalogueUserService

    @Transactional
    CatalogueUser authenticateAndObtainUserUsingOauthProvider(String oauthProviderString){
        log.info('Attempt to access system using OAUTH')

        OpenidConnectProvider openidConnectProviderProvider = openidConnectProviderService.get(Utils.toUuid(oauthProviderString))

        if(!oauthProvider) {
            log.warn('Attempt to authenticate using unknown OAUTH Provider')
            return null
        }

        CatalogueUser user = null

        try {
            HttpResponse response = HttpClient
                .create(openidConnectProviderProvider.baseUrl.toURL())
                .toBlocking()
                .exchange(
                        HttpRequest.POST(openidConnectProviderProvider.supplementalUrl, openidConnectProviderProvider.parameters)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
                            .accept(MediaType.APPLICATION_JSON_TYPE)
                )

            if (!openidConnectProviderProvider.parameters["state"] != response.properties["state"]){
                throw new SecurityException('OCAS01:', 'The response state does not match the request state.')
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



    }

}
