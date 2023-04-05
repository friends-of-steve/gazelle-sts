package net.ihe.gazelle.simulator.sts.client;

import net.ihe.gazelle.wstrust.base.RequestTypeEnum;
import net.ihe.gazelle.wstrust.base.TokenTypeEnum;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;

/**
 * Created by aberge on 03/03/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class STSRequestFactory {

    private static SOAPFactory factory;

    static {
        try {
            factory = SOAPFactory.newInstance();
        } catch (SOAPException e) {
            factory = null;
        }
    }


    /**
     * <p>createRequest.</p>
     *
     * @param requestTypeEnum a {@link net.ihe.gazelle.wstrust.base.RequestTypeEnum} object.
     * @param appliesTo a {@link java.lang.String} object.
     * @param inAssertion a {@link org.w3c.dom.Element} object.
     * @return a {@link org.w3c.dom.Element} object.
     * @throws javax.xml.soap.SOAPException if any.
     */
    public static Element createRequest(RequestTypeEnum requestTypeEnum, String appliesTo, Element inAssertion) throws
            SOAPException {
        if (factory == null) {
            factory = SOAPFactory.newInstance();
        }
        SOAPElement requestSecurityToken = factory.createElement(WsTrustConstants.REQUEST_SECURITY_TOKEN_NAME);
        SOAPElement requestType = factory.createElement(WsTrustConstants.REQUEST_TYPE_NAME);
        requestType.setTextContent(requestTypeEnum.getValue());
        requestSecurityToken.addChildElement(requestType);

        SOAPElement requestContent;
        switch (requestTypeEnum) {
            case ISSUE:
                requestContent = createIssueTarget(appliesTo);
                break;
            case CANCEL:
                requestContent = createCancelTarget(inAssertion);
                break;
            case VALIDATE:
                requestContent = createValidateTarget(inAssertion);
                break;
            case RENEW:
                requestContent = createRenewTarget(inAssertion);
                break;
            default:
                requestContent = null;
        }
        if (requestContent != null) {
            requestSecurityToken.addChildElement(requestContent);
        }

        SOAPElement tokenType = factory.createElement(WsTrustConstants.TOKEN_TYPE_NAME);
        tokenType.setTextContent(TokenTypeEnum.SAML20.getValue());
        requestSecurityToken.addChildElement(tokenType);
        return requestSecurityToken;
    }

    private static SOAPElement createCancelTarget(Element inAssertion) throws SOAPException {
        return null;
    }

    private static SOAPElement createRenewTarget(Element inAssertion) throws SOAPException {
        return null;
    }

    private static SOAPElement createIssueTarget(String appliesTo) throws SOAPException {
        SOAPElement appliesToElement = factory.createElement(WsTrustConstants.APPLIES_TO_NAME);
        SOAPElement endpointReference = factory.createElement(WsTrustConstants.ENDPOINT_REFERENCE_NAME);
        SOAPElement address = factory.createElement(WsTrustConstants.ADDRESS_NAME);
        address.setTextContent(appliesTo);
        endpointReference.addChildElement(address);
        appliesToElement.addChildElement(endpointReference);
        return appliesToElement;
    }

    private static SOAPElement createValidateTarget(Element inAssertion) throws SOAPException {
        SOAPElement validateTarget = factory.createElement(WsTrustConstants.VALIDATE_TARGET_NAME);
        Node importedElement = validateTarget.getOwnerDocument().importNode(inAssertion, true);
        validateTarget.addChildElement((SOAPElement) importedElement);
        return validateTarget;
    }
}
