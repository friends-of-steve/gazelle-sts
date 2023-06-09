package net.ihe.gazelle.sts.parsers;

import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResponseType;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.core.parsers.saml.SAMLAssertionParser;
import org.picketlink.identity.federation.core.parsers.saml.SAMLConditionsParser;
import org.picketlink.identity.federation.core.parsers.saml.SAMLSubjectParser;
import org.picketlink.identity.federation.core.parsers.util.SAMLParserUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.ActionType;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.DecisionType;
import org.picketlink.identity.federation.saml.v2.assertion.EncryptedAssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.EvidenceType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Stack;

/**
 * Created by cel on 09/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHESAMLAssertionParser extends SAMLAssertionParser {

    private static final Logger LOG = LoggerFactory.getLogger(IHESAMLAssertionParser.class);
    private static final String AUTHZ_DECISION_STATEMENT = "AuthzDecisionStatement";
    private static final String ATTRIBUTE_VALUE = "AttributeValue";
    private static final String DECISION = "Decision";
    private static final String RESOURCE = "Resource";
    private static final String ACTION = "Action";
    private static final String EVIDENCE = "Evidence";
    private static final String NAMESPACE = "Namespace";
    private final String ASSERTION = JBossSAMLConstants.ASSERTION.get();

    /** {@inheritDoc} */
    @Override
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
        StartElement startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
        String startElementName = StaxParserUtil.getStartElementName(startElement);
        if (startElementName.equals(JBossSAMLConstants.ENCRYPTED_ASSERTION.get())) {
            Element domElement = StaxParserUtil.getDOMElement(xmlEventReader);

            EncryptedAssertionType encryptedAssertion = new EncryptedAssertionType();
            encryptedAssertion.setEncryptedElement(domElement);
            return encryptedAssertion;
        }

        startElement = StaxParserUtil.getNextStartElement(xmlEventReader);

        // Special case: Encrypted Assertion
        StaxParserUtil.validate(startElement, ASSERTION);
        AssertionType assertion = parseBaseAttributes(startElement);

        // Peek at the next event
        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent == null) {
                break;
            }

            if (xmlEvent instanceof EndElement) {
                xmlEvent = StaxParserUtil.getNextEvent(xmlEventReader);
                EndElement endElement = (EndElement) xmlEvent;
                String endElementTag = StaxParserUtil.getEndElementName(endElement);
                if (endElementTag.equals(JBossSAMLConstants.ASSERTION.get())) {
                    break;
                } else {
                    throw new RuntimeException(ErrorCodes.UNKNOWN_END_ELEMENT + endElementTag);
                }
            }

            StartElement peekedElement = null;

            if (xmlEvent instanceof StartElement) {
                peekedElement = (StartElement) xmlEvent;
            } else {
                peekedElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
            }
            if (peekedElement == null) {
                break;
            }

            String tag = StaxParserUtil.getStartElementName(peekedElement);

            // Added for IHE attributes Role and PurposeOfUSe support
            if (tag.equals(ATTRIBUTE_VALUE)) {
                break;
            }
            // End of addition

            if (tag.equals(JBossSAMLConstants.SIGNATURE.get())) {
                assertion.setSignature(StaxParserUtil.getDOMElement(xmlEventReader));
                continue;
            }

            if (JBossSAMLConstants.ISSUER.get().equalsIgnoreCase(tag)) {
                startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
                String issuerValue = StaxParserUtil.getElementText(xmlEventReader);
                NameIDType issuer = new NameIDType();
                issuer.setValue(issuerValue);

                assertion.setIssuer(issuer);
            } else if (JBossSAMLConstants.SUBJECT.get().equalsIgnoreCase(tag)) {
                SAMLSubjectParser subjectParser = new SAMLSubjectParser();
                assertion.setSubject((SubjectType) subjectParser.parse(xmlEventReader));
            } else if (JBossSAMLConstants.CONDITIONS.get().equalsIgnoreCase(tag)) {
                SAMLConditionsParser conditionsParser = new SAMLConditionsParser();
                ConditionsType conditions = (ConditionsType) conditionsParser.parse(xmlEventReader);

                assertion.setConditions(conditions);
            } else if (JBossSAMLConstants.AUTHN_STATEMENT.get().equalsIgnoreCase(tag)) {
                AuthnStatementType authnStatementType = SAMLParserUtil.parseAuthnStatement(xmlEventReader);
                assertion.addStatement(authnStatementType);
            } else if (JBossSAMLConstants.ATTRIBUTE_STATEMENT.get().equalsIgnoreCase(tag)) {
                AttributeStatementType attributeStatementType = IHESAMLAttributeStatementParser
                        .parseAttributeStatement(xmlEventReader);
                assertion.addStatement(attributeStatementType);
            } else if (AUTHZ_DECISION_STATEMENT.equals(tag)) {
                AuthzDecisionStatementType authzDecisionStatementType = parseAuthzDecisionStatement(xmlEventReader);
                assertion.addStatement(authzDecisionStatementType);
            } else if (JBossSAMLConstants.STATEMENT.get().equalsIgnoreCase(tag)) {
                startElement = StaxParserUtil.getNextStartElement(xmlEventReader);

                String xsiTypeValue = StaxParserUtil.getXSITypeValue(startElement);
                if (xsiTypeValue.contains(JBossSAMLConstants.XACML_AUTHZ_DECISION_STATEMENT_TYPE.get())) {
                    XACMLAuthzDecisionStatementType authZStat = new XACMLAuthzDecisionStatementType();

                    startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
                    tag = StaxParserUtil.getStartElementName(startElement);

                    if (tag.contains(JBossSAMLConstants.RESPONSE.get())) {
                        authZStat.setResponse(getXACMLResponse(xmlEventReader));
                        startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
                        // There may be request also
                        tag = StaxParserUtil.getStartElementName(startElement);
                        if (tag.contains(JBossSAMLConstants.REQUEST.get())) {
                            authZStat.setRequest(getXACMLRequest(xmlEventReader));
                        }
                    }

                    EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
                    StaxParserUtil.validate(endElement, JBossSAMLConstants.STATEMENT.get());
                    assertion.addStatement(authZStat);
                } else {
                    throw new RuntimeException(ErrorCodes.UNKNOWN_XSI + xsiTypeValue);
                }
            } else {
                throw new RuntimeException(ErrorCodes.UNKNOWN_TAG + tag + "::location=" + peekedElement.getLocation());
            }
        }
        return assertion;
    }

    /**
     * <p>parseAuthzDecisionStatement.</p>
     *
     * @param xmlEventReader a {@link javax.xml.stream.XMLEventReader} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType} object.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     */
    protected AuthzDecisionStatementType parseAuthzDecisionStatement(XMLEventReader xmlEventReader)
            throws ParsingException {

        // AuthzDecisionStatement tag
        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        StaxParserUtil.validate(startElement, AUTHZ_DECISION_STATEMENT);
        AuthzDecisionStatementType authzDecisionStatementType = new AuthzDecisionStatementType();

        // Decision attribute
        Attribute decision = startElement.getAttributeByName(new QName(DECISION));
        if (decision == null) {
            throw new ParsingException(ErrorCodes.REQD_ATTRIBUTE + DECISION);
        }
        authzDecisionStatementType.setDecision(DecisionType.fromValue(StaxParserUtil.getAttributeValue(decision)));

        // Resource attribute
        Attribute resource = startElement.getAttributeByName(new QName(RESOURCE));
        if (decision == null) {
            throw new ParsingException(ErrorCodes.REQD_ATTRIBUTE + RESOURCE);
        }
        authzDecisionStatementType.setResource(StaxParserUtil.getAttributeValue(resource));
        // stack is used to keep the count of open/closed elements
        Stack<XMLEvent> stack = new Stack<>();

        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.getNextEvent(xmlEventReader);
            if (xmlEvent instanceof StartElement) {

                StartElement currentStartElement = (StartElement) xmlEvent;
                stack.add(currentStartElement);
                if (currentStartElement.getName().getLocalPart().equals(ACTION)) {
                    ActionType actionType = new ActionType();
                    Attribute namespace = currentStartElement.getAttributeByName(new QName(NAMESPACE));
                    if (namespace == null) {
                        throw new ParsingException(ErrorCodes.REQD_ATTRIBUTE + NAMESPACE);
                    }
                    actionType.setNamespace(StaxParserUtil.getAttributeValue(namespace));
                    String actionValue = StaxParserUtil.getElementText(xmlEventReader);
                    // The call to StaxParserUtil.getElementText() will set the xmlEventReader to the END_ELEMENT. We must pop the stack to keep the right count.
                    stack.pop();
                    actionType.setValue(actionValue);

                    authzDecisionStatementType.addAction(actionType);

                } else if (currentStartElement.getName().getLocalPart().equals(EVIDENCE)) {

                    EvidenceType evidenceType = parseEvidenceType(xmlEventReader);
                    authzDecisionStatementType.setEvidence(evidenceType);

                } else {
                    throw new ParsingException(ErrorCodes.UNKNOWN_TAG + currentStartElement.getName().getLocalPart());
                }
            } else if (xmlEvent instanceof EndElement) {
                if (!stack.isEmpty()) {
                    stack.pop();
                } else {
                    break;
                }
            }
        }

        return authzDecisionStatementType;
    }

    private EvidenceType parseEvidenceType(XMLEventReader xmlEventReader) throws ParsingException {

        EvidenceType evidenceType = new EvidenceType();
        Stack<XMLEvent> stack = new Stack<>();

        while (xmlEventReader.hasNext()) {
            XMLEvent nextXmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (nextXmlEvent instanceof StartElement) {
                StartElement currentStartElement = (StartElement) nextXmlEvent;
                stack.add(currentStartElement);

                if (currentStartElement.getName().getLocalPart().equals(ASSERTION)) {
                    AssertionType assertion = (AssertionType) this.parse(xmlEventReader);
                    evidenceType.addEvidence(new EvidenceType.ChoiceType(assertion));
                } else {
                    throw new ParsingException(ErrorCodes.UNSUPPORTED_TYPE + currentStartElement.getName()
                            .getLocalPart() + " as Evidence");
                }

            } else if (nextXmlEvent instanceof EndElement) {
                if (!stack.isEmpty()) {
                    stack.pop();
                } else {
                    break;
                }
            }

        }

        return evidenceType;

    }

    private AssertionType parseBaseAttributes(StartElement nextElement) throws ParsingException {
        Attribute idAttribute = nextElement.getAttributeByName(new QName(JBossSAMLConstants.ID.get()));
        String id = StaxParserUtil.getAttributeValue(idAttribute);

        Attribute versionAttribute = nextElement.getAttributeByName(new QName(JBossSAMLConstants.VERSION.get()));
        String version = StaxParserUtil.getAttributeValue(versionAttribute);
        StringUtil.match(JBossSAMLConstants.VERSION_2_0.get(), version);

        Attribute issueInstantAttribute = nextElement
                .getAttributeByName(new QName(JBossSAMLConstants.ISSUE_INSTANT.get()));
        XMLGregorianCalendar issueInstant = XMLTimeUtil.parse(StaxParserUtil.getAttributeValue(issueInstantAttribute));

        return new AssertionType(id, issueInstant);
    }

    @SuppressWarnings("unchecked")
    private ResponseType getXACMLResponse(XMLEventReader xmlEventReader) throws ParsingException {
        Element xacmlResponse = StaxParserUtil.getDOMElement(xmlEventReader);
        // xacml request
        String xacmlPath = "org.jboss.security.xacml.core.model.context";
        try {
            JAXBContext jaxb = JAXBContext.newInstance(xacmlPath);
            Unmarshaller un = jaxb.createUnmarshaller();
            un.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());
            JAXBElement<ResponseType> jaxbResponseType = (JAXBElement<ResponseType>) un.unmarshal(DocumentUtil
                    .getNodeAsStream(xacmlResponse));
            return jaxbResponseType.getValue();
        } catch (Exception e) {
            throw new ParsingException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private RequestType getXACMLRequest(XMLEventReader xmlEventReader) throws ParsingException {
        Element xacmlRequest = StaxParserUtil.getDOMElement(xmlEventReader);
        // xacml request
        String xacmlPath = "org.jboss.security.xacml.core.model.context";
        try {
            JAXBContext jaxb = JAXBContext.newInstance(xacmlPath);
            Unmarshaller un = jaxb.createUnmarshaller();
            un.setEventHandler(new javax.xml.bind.helpers.DefaultValidationEventHandler());
            JAXBElement<RequestType> jaxbRequestType = (JAXBElement<RequestType>) un.unmarshal(DocumentUtil
                    .getNodeAsStream(xacmlRequest));
            return jaxbRequestType.getValue();
        } catch (Exception e) {
            throw new ParsingException(e);
        }
    }

}
