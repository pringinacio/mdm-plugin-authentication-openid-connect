package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect


import grails.testing.services.ServiceUnitTest
import grails.testing.web.interceptor.InterceptorUnitTest
import groovy.util.logging.Slf4j
import uk.ac.ox.softeng.maurodatamapper.core.container.ClassifierInterceptor
import uk.ac.ox.softeng.maurodatamapper.test.unit.BaseUnitSpec
import uk.ac.ox.softeng.maurodatamapper.test.unit.interceptor.ResourceInterceptorUnitSpec


@Slf4j
class OpenidConnectProviderInterceptorSpec extends ResourceInterceptorUnitSpec implements InterceptorUnitTest<ClassifierInterceptor> {


    @Override
    String getControllerName() {
        return null
    }
}
