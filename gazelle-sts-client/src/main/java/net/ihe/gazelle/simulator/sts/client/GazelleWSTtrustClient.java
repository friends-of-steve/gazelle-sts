package net.ihe.gazelle.simulator.sts.client;

import net.ihe.gazelle.sts.constants.AssertionProfile;
import net.ihe.gazelle.wstrust.addressing.EndpointReferenceType;
import net.ihe.gazelle.wstrust.base.CancelTargetType;
import net.ihe.gazelle.wstrust.base.RenewTargetType;
import net.ihe.gazelle.wstrust.base.RequestSecurityTokenResponseCollectionType;
import net.ihe.gazelle.wstrust.base.RequestSecurityTokenResponseType;
import net.ihe.gazelle.wstrust.base.RequestSecurityTokenType;
import net.ihe.gazelle.wstrust.base.RequestTypeEnum;
import net.ihe.gazelle.wstrust.base.RequestedTokenCancelledType;
import net.ihe.gazelle.wstrust.base.StatusCodeEnum;
import net.ihe.gazelle.wstrust.base.StatusType;
import net.ihe.gazelle.wstrust.base.TokenTypeEnum;
import net.ihe.gazelle.wstrust.base.ValidateTargetType;
import net.ihe.gazelle.wstrust.policy.AppliesToType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.soap.AddressingFeature;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by aberge on 23/02/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class GazelleWSTtrustClient {

    /** Constant <code>UTF_8="UTF-8"</code> */
    public static final String UTF_8 = "UTF-8";
    /** Constant <code>NONCE_LENGTH=16</code> */
    public static final int NONCE_LENGTH = 16;
    private static final Logger LOG = LoggerFactory.getLogger(GazelleWSTtrustClient.class);
    private String endpointUrl;
    private StatusCodeEnum statusCode;
    private String invalidReason;


    /**
     * <p>Constructor for GazelleWSTtrustClient.</p>
     *
     * @param endpointUrl a {@link java.lang.String} object.
     */
    public GazelleWSTtrustClient(String endpointUrl) {
        this.endpointUrl = endpointUrl;
    }

    /**
     * <p>validateAssertion.</p>
     *
     * @param assertionToValidate a {@link org.w3c.dom.Element} object.
     * @return a boolean.
     */
    public boolean validateAssertion(Element assertionToValidate) {
        Element requestSecurityTokenType;
        try {
            requestSecurityTokenType = STSRequestFactory
                    .createRequest(RequestTypeEnum.VALIDATE, null, assertionToValidate);
        } catch (SOAPException e) {
            statusCode = null;
            invalidReason = "Cannot build request: " + e.getMessage();
            return false;
        }
        RequestSecurityTokenResponseCollectionType response = sendAndGetResponse(requestSecurityTokenType,
                STSActionEnum.VALIDATE, null);
        if (response != null && !response.getRequestSecurityTokenResponse().isEmpty()) {
            RequestSecurityTokenResponseType tokenResponse = getFirstOccurence(response);
            StatusType status = tokenResponse.getStatus();
            if (status != null) {
                statusCode = status.getCode();
                invalidReason = status.getReason();
                return StatusCodeEnum.VALID.equals(status.getCode());
            } else {
                statusCode = null;
                invalidReason = "Cannot access status in STS response";
                return false;
            }
        } else {
            statusCode = null;
            invalidReason = "Cannot get response from STS";
            return false;
        }
    }

    /**
     * <p>issueAssertion.</p>
     *
     * @param assertionProfile a {@link net.ihe.gazelle.sts.constants.AssertionProfile} object.
     * @param appliesToUrl a {@link java.lang.String} object.
     * @return a {@link org.w3c.dom.Element} object.
     * @throws java.lang.Exception if any.
     */
    public Element issueAssertion(AssertionProfile assertionProfile, String appliesToUrl) throws Exception {
        Element requestSecurityTokenType = STSRequestFactory.createRequest(RequestTypeEnum.ISSUE, appliesToUrl, null);
        STSCredentials credentials = new STSCredentials(assertionProfile.getName(), assertionProfile.getPassword());
        try {
            SOAPBody response = send(requestSecurityTokenType, STSActionEnum.ISSUE, credentials);
            return extractAssertionFromResponse(response);
        } catch (Exception e) {
            LOG.error(e.getMessage());
            e.printStackTrace();
            throw new Exception("Cannot get assertion", e);
        }
    }

    /**
     * <p>issueAssertion.</p>
     *
     * @param credentials a {@link net.ihe.gazelle.simulator.sts.client.STSCredentials} object.
     * @param appliesToUrl a {@link java.lang.String} object.
     * @return a {@link org.w3c.dom.Element} object.
     * @throws java.lang.Exception if any.
     */
    @Deprecated
    public Element issueAssertion(STSCredentials credentials, String appliesToUrl) throws Exception {
        Element requestSecurityTokenType = STSRequestFactory.createRequest(RequestTypeEnum.ISSUE, appliesToUrl, null);
        try {
            SOAPBody response = send(requestSecurityTokenType, STSActionEnum.ISSUE, credentials);
            return extractAssertionFromResponse(response);
        } catch (Exception e) {
            LOG.error(e.getMessage());
            e.printStackTrace();
            throw new Exception("Cannot get assertion", e);
        }
    }

    /**
     * <p>createRequest.</p>
     *
     * @param requestType a {@link net.ihe.gazelle.wstrust.base.RequestTypeEnum} object.
     * @param appliesTo a {@link java.lang.String} object.
     * @param inAssertion a {@link org.w3c.dom.Element} object.
     * @return a {@link net.ihe.gazelle.wstrust.base.RequestSecurityTokenType} object.
     */
    public RequestSecurityTokenType createRequest(RequestTypeEnum requestType, String appliesTo, Element inAssertion) {
        RequestSecurityTokenType requestSecurityTokenType = new RequestSecurityTokenType();
        requestSecurityTokenType.setRequestType(requestType);
        requestSecurityTokenType.setTokenType(TokenTypeEnum.SAML20);
        switch (requestType) {
            case CANCEL:
                fillCancelAssertionRequest(requestSecurityTokenType, inAssertion);
                break;
            case RENEW:
                fillRenewAssertionRequest(requestSecurityTokenType, inAssertion);
                break;
            case VALIDATE:
                fillValidateAssertionRequest(requestSecurityTokenType, inAssertion);
                break;
            case ISSUE:
                fillIssueAssertionRequest(requestSecurityTokenType, appliesTo);
                break;
            default:
                LOG.warn(requestType.getValue() + " is not a supported request type");
                break;
        }
        return requestSecurityTokenType;
    }

    private JAXBElement convertElement(Element element) {
        QName qName = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        return new JAXBElement(qName, Element.class, element);
    }

    private void fillCancelAssertionRequest(RequestSecurityTokenType requestSecurityTokenType, Element inAssertion) {
        CancelTargetType cancel = new CancelTargetType();
        cancel.setAssertion(convertElement(inAssertion));
        requestSecurityTokenType.setCancelTarget(cancel);
    }

    private void fillRenewAssertionRequest(RequestSecurityTokenType requestSecurityTokenType, Element inAssertion) {
        RenewTargetType renew = new RenewTargetType();
        renew.setAssertion(convertElement(inAssertion));
        requestSecurityTokenType.setRenewTarget(renew);
    }

    private void fillValidateAssertionRequest(RequestSecurityTokenType requestSecurityTokenType, Element inAssertion) {
        ValidateTargetType validate = new ValidateTargetType();
        validate.setAssertion(convertElement(inAssertion));
        requestSecurityTokenType.setValidateTarget(validate);
    }

    private void fillIssueAssertionRequest(RequestSecurityTokenType request, String appliesToUrl) {
        AppliesToType appliesTo = new AppliesToType();
        EndpointReferenceType endpointReference = new EndpointReferenceType();
        endpointReference.setAddress(appliesToUrl);
        appliesTo.setEndpointReference(endpointReference);
        request.setAppliesTo(appliesTo);
    }

    /**
     * Not yet implemented on Gazelle STS service side
     *
     * @param assertionToCancel a {@link org.w3c.dom.Element} object.
     * @return false if anything unexpected appends, true otherwise
     */
    public boolean cancelAssertion(Element assertionToCancel) {
        Element requestSecurityTokenType;
        try {
            requestSecurityTokenType = STSRequestFactory.createRequest(RequestTypeEnum.CANCEL, null, assertionToCancel);
        } catch (SOAPException e) {
            return false;
        }
        RequestSecurityTokenResponseCollectionType response = sendAndGetResponse(requestSecurityTokenType,
                STSActionEnum.CANCEL, null);
        if (response != null && !response.getRequestSecurityTokenResponse().isEmpty()) {
            RequestSecurityTokenResponseType tokenResponse = getFirstOccurence(response);
            RequestedTokenCancelledType cancelled = tokenResponse.getRequestedTokenCancelled();
            return cancelled != null;
        } else {
            return false;
        }
    }

    /**
     * <p>renewAssertion.</p>
     *
     * @param assertionToRenew a {@link org.w3c.dom.Element} object.
     * @return a {@link org.w3c.dom.Element} object.
     * @throws java.lang.Exception if any.
     */
    public Element renewAssertion(Element assertionToRenew) throws Exception {
        Element requestSecurityTokenType;
        try {
            requestSecurityTokenType = STSRequestFactory.createRequest(RequestTypeEnum.RENEW, null, assertionToRenew);
        } catch (SOAPException e) {
            return null;
        }
        SOAPBody response = send(requestSecurityTokenType, STSActionEnum.RENEW, null);
        return extractAssertionFromResponse(response);
    }

    private Element extractAssertionFromResponse(SOAPBody soapBody) {
        if (soapBody != null) {
            NodeList assertions = soapBody.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
            if (assertions != null && assertions.getLength() > 0) {
                return (Element) assertions.item(0);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }


    private RequestSecurityTokenResponseType getFirstOccurence(RequestSecurityTokenResponseCollectionType response) {
        return response.getRequestSecurityTokenResponse().get(0);
    }

    private SOAPBody send(Element request,
                          STSActionEnum stsAction,
                          STSCredentials credentials) throws SOAPException, MalformedURLException {
        URL endpoint = new URL(endpointUrl);
        SOAPMessage msg = createSoapMessage();
        QName serviceQName = new QName("urn:gazelle.ihe.net:sts", "GazelleSTS");
        QName portQName = new QName("urn:gazelle.ihe.net:sts", "GazelleSTSPort");
        Service service = Service.create(endpoint, serviceQName);
        Dispatch<SOAPMessage> dispatch = service.createDispatch(portQName, SOAPMessage.class, Service.Mode.MESSAGE,
                new AddressingFeature(true, true));
        dispatch.getRequestContext().put(BindingProvider.SOAPACTION_USE_PROPERTY, true);
        dispatch.getRequestContext().put(BindingProvider.SOAPACTION_URI_PROPERTY, stsAction.getSoapAction());
        if (credentials == null) {
            credentials = STSCredentials.defaultCredentials();
        }
        // HTTP Basic authentication
        Map<String, List<String>> headers = new HashMap<String, List<String>>();
        headers.put("Authorization", Arrays.asList(credentials.getBasicAuthenticator()));
        dispatch.getRequestContext().put(MessageContext.HTTP_REQUEST_HEADERS, headers);

        // add soap body
        Node importedBody = msg.getSOAPBody().getOwnerDocument().importNode(request, true);
        msg.getSOAPBody().appendChild(importedBody);

        // send message
        SOAPMessage response = dispatch.invoke(msg);
        if (response != null) {
            return response.getSOAPBody();
        } else {
            throw new SOAPException("Unable to extract node from request");
        }
    }

    private RequestSecurityTokenResponseCollectionType sendAndGetResponse(Element request,
                                                                          STSActionEnum stsAction,
                                                                          STSCredentials credentials) {
        try {
            SOAPBody responseBody = send(request, stsAction, credentials);
            SOAPFault fault = responseBody.getFault();
            if (fault != null && fault.getDetail() != null) {
                throw new SOAPException(fault.getDetail().getValue());
            } else {
                Document bodyContent = responseBody.extractContentAsDocument();
                JAXBContext jc = JAXBContext.newInstance(RequestSecurityTokenResponseCollectionType.class);
                Unmarshaller unmarshaller = jc.createUnmarshaller();
                JAXBElement<RequestSecurityTokenResponseCollectionType> jaxbElement = unmarshaller
                        .unmarshal(bodyContent, RequestSecurityTokenResponseCollectionType.class);
                return jaxbElement.getValue();
            }
        } catch (Exception e) {
            e.printStackTrace();
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    private SOAPMessage createSoapMessage() throws SOAPException {
        MessageFactory mf = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);
        return mf.createMessage();
    }

    /**
     * <p>Getter for the field <code>statusCode</code>.</p>
     *
     * @return a {@link net.ihe.gazelle.wstrust.base.StatusCodeEnum} object.
     */
    public StatusCodeEnum getStatusCode() {
        return this.statusCode;
    }

    /**
     * <p>Getter for the field <code>invalidReason</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getInvalidReason() {
        return this.invalidReason;
    }
}
