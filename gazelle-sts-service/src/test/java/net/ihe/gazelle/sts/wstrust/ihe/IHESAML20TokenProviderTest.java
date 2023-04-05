package net.ihe.gazelle.sts.wstrust.ihe;

import net.ihe.gazelle.sts.config.AssertionProperties;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.Principal;

import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class IHESAML20TokenProviderTest {

    @Mock
    Principal principalMock;
    @Mock
    WSTrustRequestContext contextMock;
    @Mock
    AssertionProperties assertionProperties;


    @Before
    public void setUp() throws IOException {
        principalMock = mock(Principal.class);
        contextMock = mock(WSTrustRequestContext.class);
        assertionProperties = mock(AssertionProperties.class);
        when(principalMock.getName()).thenReturn("valid");
        when(contextMock.getTokenIssuer()).thenReturn("issuer@gazelle.com");
    }


    @Test
    public void getIssuerNameIDTypeIssuerEmailTest() {
        IHESAML20TokenProvider ihesaml20TokenProvider = new IHESAML20TokenProvider();
        NameIDType nameIDType = ihesaml20TokenProvider.getIssuerNameIDType(contextMock, principalMock);
        Assert.assertEquals("nameId value should be equal to issuer@gazelle.com", "issuer@gazelle.com", nameIDType.getValue());
        Assert.assertEquals("nameId format should be equal to urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", nameIDType.getFormat().toString());
    }

    @Test
    public void getIssuerNameIDTypeInvalidIssuerWindowsTest() {
        when(principalMock.getName()).thenReturn("invalidissuerwindowsdomainformat");
        when(contextMock.getTokenIssuer()).thenReturn("issuer");
        IHESAML20TokenProvider ihesaml20TokenProvider = new IHESAML20TokenProvider();
        NameIDType nameIDType = ihesaml20TokenProvider.getIssuerNameIDType(contextMock, principalMock);
        Assert.assertEquals("nameId value should be equal to .NotValidWindowsDomain.QualifierName?", ".NotValidWindowsDomain.QualifierName?", nameIDType.getValue());
        Assert.assertEquals("nameId format should be equal to urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", nameIDType.getFormat().toString());
    }


    @Test
    public void getIssuerNameIDTypeInvalidIssuerEmailFormatTest() {
        when(principalMock.getName()).thenReturn("invalidissueremailformat");
        IHESAML20TokenProvider ihesaml20TokenProvider = new IHESAML20TokenProvider();
        NameIDType nameIDType = ihesaml20TokenProvider.getIssuerNameIDType(contextMock, principalMock);
        Assert.assertEquals("nameId value should be equal to issuergazelle.com", "issuergazelle.com", nameIDType.getValue());
        Assert.assertEquals("nameId format should be equal to urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", nameIDType.getFormat().toString());
    }

}
