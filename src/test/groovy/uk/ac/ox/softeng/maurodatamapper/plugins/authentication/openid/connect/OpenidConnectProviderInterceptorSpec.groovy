package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect


import grails.testing.web.interceptor.InterceptorUnitTest
import grails.views.mvc.GenericGroovyTemplateViewResolver
import groovy.util.logging.Slf4j
import io.micronaut.http.HttpStatus
import org.grails.web.servlet.view.CompositeViewResolver
import org.grails.web.util.GrailsApplicationAttributes
import spock.lang.Unroll
import uk.ac.ox.softeng.maurodatamapper.security.basic.NoAccessSecurityPolicyManager
import uk.ac.ox.softeng.maurodatamapper.security.basic.PublicAccessSecurityPolicyManager
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec
import uk.ac.ox.softeng.maurodatamapper.test.unit.security.IdSecuredUserSecurityPolicyManager


@Slf4j
class OpenidConnectProviderInterceptorSpec extends BaseUnitSpec implements InterceptorUnitTest<OpenidConnectProviderInterceptor> {

    static UUID unknownId = UUID.randomUUID()
    static UUID readAccessId = UUID.randomUUID()
    static UUID noAccessId = UUID.randomUUID()
    static UUID writeAccessId = UUID.randomUUID()
    static IdSecuredUserSecurityPolicyManager idSecuredUserSecurityPolicyManager
    static IdSecuredUserSecurityPolicyManager applicationAdminSecuredUserSecurityPolicyManager

    def setupSpec() {
        log.debug('Setting up resource unit spec')
        unknownId = UUID.randomUUID()
        readAccessId = UUID.randomUUID()
        noAccessId = UUID.randomUUID()
        writeAccessId = UUID.randomUUID()

        idSecuredUserSecurityPolicyManager = new IdSecuredUserSecurityPolicyManager(editor, unknownId, noAccessId, readAccessId, writeAccessId)
        applicationAdminSecuredUserSecurityPolicyManager = new IdSecuredUserSecurityPolicyManager(admin, unknownId, noAccessId, readAccessId,
                writeAccessId)

        // The grails unit spec loads th composite view resolver but only with the gsp resolver
        // We need to add the jsonViewResolver
        // Weirdly the base spec does create the smart view resolvers so they are available as referenced beans
        defineBeans {
            jsonViewResolver(GenericGroovyTemplateViewResolver, ref('jsonSmartViewResolver'))
            "${CompositeViewResolver.BEAN_NAME}"(CompositeViewResolver)
        }
    }


    void setResourceIdParameter(String id, String action) {
        if (action != 'index') params.id = id
    }

    void setAnyInitialParams() {
        // Default is no-op
    }

    boolean getNoAccessIndexAllowedState() {
        false
    }

    HttpStatus getNoAccessIndexAllowedCode() {
        HttpStatus.FORBIDDEN
    }

    HttpStatus getSaveAllowedCode() {
        HttpStatus.FORBIDDEN
    }

    def getPublicAccessUserSecurityPolicyManager() {
        PublicAccessSecurityPolicyManager.instance
    }

    def getNoAccessUserSecurityPolicyManager() {
        NoAccessSecurityPolicyManager.instance
    }

    String getControllerName() {
        'openidConnectProvider'
    }

    void 'R1 : Test interceptor matching'() {
        when: 'A request matches the interceptor'
        withRequest(controller: controllerName)

        then: 'The interceptor does match'
        interceptor.doesMatch()

    }

    @Unroll
    void 'R2 : test public access to #action is allowed'() {
        given:
        setAnyInitialParams()
        params.currentUserSecurityPolicyManager = publicAccessUserSecurityPolicyManager

        when:
        withRequest(controller: controllerName)
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)

        then:
        interceptor.before()

        where:
        action << [
                'index',
                'show',
                'save',
                'update',
                'delete'
        ]
    }

    @Unroll
    void 'R3 : test no access to #action is allowed (#allowed)'() {
        given:
        setAnyInitialParams()
        params.openAccess = true
        params.currentUserSecurityPolicyManager = noAccessUserSecurityPolicyManager

        when:
        withRequest([controller: controllerName])
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)

        then:
        interceptor.before() == allowed

        and:
        response.status == responseCode.code

        where:
        action   || allowed | responseCode
        'index'  || true    | HttpStatus.OK
        'show'   || false   | HttpStatus.FORBIDDEN
        'save'   || false   | HttpStatus.FORBIDDEN
        'update' || false   | HttpStatus.FORBIDDEN
        'delete' || false   | HttpStatus.FORBIDDEN
    }

    @Unroll
    void 'R4 : test admin access to #action is allowed (#allowed)'() {
        given:
        setAnyInitialParams()
        params.currentUserSecurityPolicyManager = applicationAdminSecuredUserSecurityPolicyManager

        when:
        withRequest([controller: controllerName])
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)

        then:
        interceptor.before() == allowed

        and:
        response.status == responseCode.code

        where:
        action   || allowed | responseCode
        'index'  || true    | HttpStatus.OK
        'show'   || true    | HttpStatus.OK
        'save'   || true    | HttpStatus.OK
        'update' || true    | HttpStatus.OK
        'delete' || true    | HttpStatus.OK
    }

    @Unroll
    void 'R5 : test read/write access to #action is controlled for #type resource'() {
        given:
        params.currentUserSecurityPolicyManager = idSecuredUserSecurityPolicyManager

        when:
        setResourceIdParameter(resourceId.toString(), action)
        withRequest([controller: controllerName])
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)

        then:
        !interceptor.before()

        and:
        response.status == HttpStatus.FORBIDDEN.code

        where:
        action   | resourceId
        'show'   | unknownId
        'show'   | noAccessId
        'show'   | readAccessId
        'show'   | writeAccessId
        'save'   | unknownId
        'save'   | noAccessId
        'save'   | readAccessId
        'save'   | writeAccessId
        'update' | unknownId
        'update' | noAccessId
        'update' | readAccessId
        'update' | writeAccessId
        'delete' | unknownId
        'delete' | noAccessId
        'delete' | readAccessId
        'delete' | writeAccessId

        type = resourceId == unknownId ? 'unknown' :
                resourceId == noAccessId ? 'no access' :
                        resourceId == readAccessId ? 'read access' :
                                resourceId == writeAccessId ? 'write access' : 'broken'
    }
}
