package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.gorm.transactions.Transactional

@Transactional
class OpenidConnectProviderService {

    OpenidConnectProvider get(Serializable id){
        OpenidConnectProvider.get(id)
    }

    int count(){
        OpenidConnectProvider.count()
    }

    List<OpenidConnectProvider> list(Map pagination){
        pagination ? OpenidConnectProvider.list(pagination) : OpenidConnectProvider.list()
    }

    void save(OpenidConnectProvider openidConnectProvider){
        openidConnectProvider.save(failOnError: true, validate: false)
    }

    void delete(OpenidConnectProvider openidConnectProvider){
        openidConnectProvider.delete(flush: true)
    }

    OpenidConnectProvider findByOpenidConnectProviderType(OpenidConnectProviderType openidConnectProviderType){
        OpenidConnectProvider.findByOpenidConnectProviderType(openidConnectProviderType)
    }

    OpenidConnectProvider findByLabel(String label){
        OpenidConnectProvider.findByLabel(label)
    }
}
