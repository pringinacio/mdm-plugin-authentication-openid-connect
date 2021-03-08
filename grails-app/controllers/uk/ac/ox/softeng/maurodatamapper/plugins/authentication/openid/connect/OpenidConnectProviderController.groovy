package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect


import org.springframework.beans.factory.annotation.Autowired
import uk.ac.ox.softeng.maurodatamapper.core.container.Classifier
import uk.ac.ox.softeng.maurodatamapper.core.controller.EditLoggingController
import uk.ac.ox.softeng.maurodatamapper.security.SecurityPolicyManagerService

class OpenidConnectProviderController extends EditLoggingController<OpenidConnectProvider>{
	static responseFormats = ['json', 'xml']

    @Autowired(required=false)
    SecurityPolicyManagerService securityPolicyManagerService

    OpenidConnectProviderService openidConnectProviderService

    def index() { }

    OpenidConnectProviderController(){
        super(OpenidConnectProvider)
    }


    @Override
    protected OpenidConnectProvider saveResource(OpenidConnectProvider resource){
        OpenidConnectProvider oauthProvider = super.saveResource(resource) as OpenidConnectProvider

        if (securityPolicyManagerService){
            currentUserSecurityPolicyManager = securityPolicyManagerService.addSecurityForSecurableResource(resource, currentUser, resource.label)
        }

        oauthProvider
    }

    @Override
    void serviceDeleteResource(OpenidConnectProvider resource){
        openidConnectProviderService.delete(resource)
    }

    @Override
    protected List<OpenidConnectProvider> listAllReadableResources(Map params) {
        params.sort = params.sort ?: 'label'
        openidConnectProviderService.list(currentUserSecurityPolicyManager, params)
    }
}
