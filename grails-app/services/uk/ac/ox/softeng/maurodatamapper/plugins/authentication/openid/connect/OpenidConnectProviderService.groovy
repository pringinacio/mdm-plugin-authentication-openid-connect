package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.gorm.transactions.Transactional

@Transactional
class OpenidConnectProviderService {

    OpenidConnectProvider get(Serializable id){
        OpenidConnectProvider.get(id)
    }

    List<OpenidConnectProvider> list(Map pagination){
        pagination ? OpenidConnectProvider.list(pagination) : OpenidConnectProvider.list()
    }

    void delete(OpenidConnectProvider oauthProvider){
        oauthProvider.delete(flush: true)
    }

}
