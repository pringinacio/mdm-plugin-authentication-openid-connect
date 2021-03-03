package uk.ac.ox.softeng.maurodatamapper.plugins.authentication.openid.connect

import grails.testing.web.interceptor.InterceptorUnitTest
import spock.lang.Specification

class OpenidConnectProviderInterceptorSpec extends Specification implements InterceptorUnitTest<OpenidConnectProviderInterceptor> {

    def setup() {
    }

    def cleanup() {

    }

    void "Test oauthProvider interceptor matching"() {
        when:"A request matches the interceptor"
        withRequest(controller:"oauthProvider")

        then:"The interceptor does match"
        interceptor.doesMatch()
    }
}
