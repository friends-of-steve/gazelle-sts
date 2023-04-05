package net.ihe.gazelle.sts.writers;

import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.StaxUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLAssertionWriter;
import org.picketlink.identity.federation.saml.v2.assertion.AdviceType;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.EvidenceType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.picketlink.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;

/**
 * Created by cel on 09/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHESAMLAssertionWriter extends SAMLAssertionWriter {

    private static final Logger LOG = LoggerFactory.getLogger(IHESAMLAssertionWriter.class);

    private static final String AUTHZ_DECISION_STATEMENT_ELEMENT_NAME = "AuthzDecisionStatement";

    /**
     * <p>Constructor for IHESAMLAssertionWriter.</p>
     *
     * @param writer a {@link javax.xml.stream.XMLStreamWriter} object.
     */
    public IHESAMLAssertionWriter(XMLStreamWriter writer) {
        super(writer);
        ASSERTION_PREFIX = "saml2";
    }

    /** {@inheritDoc} */
    @Override
    public void write(AssertionType assertion) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ASSERTION.get(), ASSERTION_NSURI.get());
        StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
        StaxUtil.writeDefaultNameSpace(writer, ASSERTION_NSURI.get());


        // Added by Matt Blackmon MLB: 10-3-2020 Add the xs namespace instance
        //logger.warn("MLB Logger WARN: IHESAMLAssertionWriter - Attempting to add the xsi namespace " + JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());

        //I can write the attribute fine... need the namespace....
        //StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(),  "xmlns", attributeValue.getXmlns() );


        //StaxUtil.writeAttribute(writer, "xs", JBossSAMLURIConstants.XSI_NSURI.get(), "xmlns", "http://www.w3.org/2001/XMLSchema");

        //StaxUtil.setPrefix(writer,"xsi", "http://www.w3.org/2001/XMLSchema-instance");
        //StaxUtil.writeNameSpace(writer,"xsi", "http://www.w3.org/2001/XMLSchema-instance");

        //StaxUtil.setPrefix(writer,"xs", "http://www.w3.org/2001/XMLSchema");
        //StaxUtil.writeNameSpace(writer,"xs", "http://www.w3.org/2001/XMLSchema");

        //logger.warn(" MLB Inside write trying to add:" + ASSERTION_PREFIX + " value:" + JBossSAMLConstants.ATTRIBUTE_VALUE.get() + " ASSERTION_NSURI:" + ASSERTION_NSURI.get());
        //StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        //logger.warn("MLB Inside write trying to add ns prefix:" + JBossSAMLURIConstants.XSI_PREFIX.get() + " Namespace:" + JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());
        //StaxUtil.writeNameSpace(writer, "xsmlb", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());

        //THIS IS THE WORKING EXAMPLE FROM BELOW:
        //StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "xmlns",
        //                attributeValue.getXmlns());
        //THIS IS NOT WORKING

        // MLB 4-3-2023
        // StaxUtil.setPrefix(writer, "xs", "http://www.w3.org/2001/XMLSchema");
        // StaxUtil.writeAttribute(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get(), "xmlns", "http://www.w3.org/2001/XMLSchema");


        // Attributes
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), assertion.getID());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.VERSION.get(), assertion.getVersion());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISSUE_INSTANT.get(), assertion.getIssueInstant().toString());

        NameIDType issuer = assertion.getIssuer();
        if (issuer != null) {
            write(issuer, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get(), ASSERTION_PREFIX));
        }

        Element sig = assertion.getSignature();
        if (sig != null) {
            StaxUtil.writeDOMElement(writer, sig);
        }

        SubjectType subject = assertion.getSubject();
        if (subject != null) {
            write(subject);
        }

        ConditionsType conditions = assertion.getConditions();
        if (conditions != null) {
            StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.CONDITIONS.get(),
                    ASSERTION_NSURI.get());

            if (conditions.getNotBefore() != null) {
                StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(),
                        conditions.getNotBefore().toString());
            }

            if (conditions.getNotOnOrAfter() != null) {
                StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(),
                        conditions.getNotOnOrAfter().toString());
            }

            List<ConditionAbstractType> typeOfConditions = conditions.getConditions();
            if (typeOfConditions != null) {
                for (ConditionAbstractType typeCondition : typeOfConditions) {
                    if (typeCondition instanceof AudienceRestrictionType) {
                        AudienceRestrictionType art = (AudienceRestrictionType) typeCondition;
                        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX,
                                JBossSAMLConstants.AUDIENCE_RESTRICTION.get(),
                                ASSERTION_NSURI.get());
                        List<URI> audiences = art.getAudience();
                        if (audiences != null) {
                            for (URI audience : audiences) {
                                StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE.get(),
                                        ASSERTION_NSURI.get());
                                StaxUtil.writeCharacters(writer, audience.toString());
                                StaxUtil.writeEndElement(writer);
                            }
                        }

                        StaxUtil.writeEndElement(writer);
                    }
                }
            }

            StaxUtil.writeEndElement(writer);
        }

        AdviceType advice = assertion.getAdvice();
        if (advice != null) {
            throw logger.notImplementedYet("Advice");
        }

        Set<StatementAbstractType> statements = assertion.getStatements();
        if (statements != null) {
            for (StatementAbstractType statement : statements) {
                if (statement instanceof AuthnStatementType) {
                    write((AuthnStatementType) statement);
                } else if (statement instanceof AttributeStatementType) {
                    write((AttributeStatementType) statement);
                } else if (statement instanceof AuthzDecisionStatementType) {
                    write((AuthzDecisionStatementType) statement);
                } else if (statement instanceof XACMLAuthzDecisionStatementType) {
                    write((XACMLAuthzDecisionStatementType) statement);
                } else {
                    throw logger.writerUnknownTypeError(statement.getClass().getName());
                }
            }
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * <p>write.</p>
     *
     * @param authzDecStat a {@link org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType} object.
     * @throws org.picketlink.common.exceptions.ProcessingException if any.
     */
    public void write(AuthzDecisionStatementType authzDecStat) throws ProcessingException {

        // AuthzDecisionStatment
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, AUTHZ_DECISION_STATEMENT_ELEMENT_NAME,
                ASSERTION_NSURI.get());
        StaxUtil.writeAttribute(writer, "Decision", authzDecStat.getDecision().value());
        StaxUtil.writeAttribute(writer, "Resource", authzDecStat.getResource());

        writeAction();
        if (authzDecStat.getEvidence() != null) {
            writeEvidence(authzDecStat.getEvidence());
        }

        // End of AuthzDecisionStatment
        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);

    }

    /**
     * <p>writeEvidence.</p>
     *
     * @param evidenceType a {@link org.picketlink.identity.federation.saml.v2.assertion.EvidenceType} object.
     * @throws org.picketlink.common.exceptions.ProcessingException if any.
     */
    protected void writeEvidence(EvidenceType evidenceType) throws ProcessingException {
        // AuthzDecisionStatement/Evidence
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, "Evidence", ASSERTION_NSURI.get());
        for (EvidenceType.ChoiceType evidence : evidenceType.evidences()) {
            if (evidence.getAssertion() != null) {
                this.write(evidence.getAssertion());
            } else if (evidence.getAssertionIDRef() != null) {
                throw logger.notImplementedYet("Writer for AuthzDecisionStatement/Evidence/AssertionIdRef");
            } else if (evidence.getAssertionURIRef() != null) {
                throw logger.notImplementedYet("Writer for AuthzDecisionStatement/Evidence/AssertionURIRef");
            } else if (evidence.getEncryptedAssertion() != null) {
                throw logger.notImplementedYet("Writer for AuthzDecisionStatement/Evidence/EncryptedAssertion");
            }
        }
        StaxUtil.writeEndElement(writer);
    }

    /**
     * <p>writeAction.</p>
     *
     * @throws org.picketlink.common.exceptions.ProcessingException if any.
     */
    protected void writeAction() throws ProcessingException {
        // AuthzDecisionStatment/Action
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, "Action", ASSERTION_NSURI.get());
        StaxUtil.writeAttribute(writer, "Namespace", "urn:oasis:names:tc:SAML:1.0:action:rwedc");
        StaxUtil.writeCharacters(writer, "Execute");
        StaxUtil.writeEndElement(writer);
    }

    /** {@inheritDoc} */
    @Override
    public void writeAttributeTypeWithoutRootTag(AttributeType attributeType) throws ProcessingException {
        String attributeName = attributeType.getName();
        if (attributeName != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME.get(), attributeName);
        }

        String friendlyName = attributeType.getFriendlyName();
        if (StringUtil.isNotNull(friendlyName)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.FRIENDLY_NAME.get(), friendlyName);
        }

        String nameFormat = attributeType.getNameFormat();
        if (StringUtil.isNotNull(nameFormat)) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.NAME_FORMAT.get(), nameFormat);
        }

        // Take care of other attributes such as x500:encoding
        Map<QName, String> otherAttribs = attributeType.getOtherAttributes();
        if (otherAttribs != null) {
            List<String> nameSpacesDealt = new ArrayList<String>();

            Iterator<QName> keySet = otherAttribs.keySet().iterator();
            while (keySet != null && keySet.hasNext()) {
                QName qname = keySet.next();
                String ns = qname.getNamespaceURI();
                if (!nameSpacesDealt.contains(ns)) {
                    StaxUtil.writeNameSpace(writer, qname.getPrefix(), ns);
                    nameSpacesDealt.add(ns);
                }
                String attribValue = otherAttribs.get(qname);
                StaxUtil.writeAttribute(writer, qname, attribValue);
            }
        }

        List<Object> attributeValues = attributeType.getAttributeValue();
        if (attributeValues != null) {
            for (Object attributeValue : attributeValues) {
                if (attributeValue != null) {
                    if (attributeValue instanceof String) {
                        writeStringAttributeValue((String) attributeValue);
                    } else if (attributeValue instanceof HL7v3CodedElementInterface) {
                        writeHL7v3CodedElementAttributeValue((HL7v3CodedElementInterface) attributeValue);
                    } else {
                        throw logger.writerUnsupportedAttributeValueError(attributeValue.getClass().getName());
                    }
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void writeStringAttributeValue(String attributeValue) throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(),
                ASSERTION_NSURI.get());

        //MLB 10-9-2020 added from original code... error in deletion?

        // 4-3-13 MLB
        StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        //StaxUtil.writeNameSpace(writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get());

        if (attributeValue.startsWith("urn:oid")) {
            StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:anyURI");
        } else {
            StaxUtil.writeAttribute(writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:string");
        }
        StaxUtil.writeCharacters(writer, attributeValue);
        StaxUtil.writeEndElement(writer);
    }

    /**
     * <p>writeHL7v3CodedElementAttributeValue.</p>
     *
     * @param attributeValue a {@link net.ihe.gazelle.sts.writers.HL7v3CodedElementInterface} object.
     * @throws org.picketlink.common.exceptions.ProcessingException if any.
     */
    public void writeHL7v3CodedElementAttributeValue(HL7v3CodedElementInterface attributeValue)
            throws ProcessingException {
        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get(),
                ASSERTION_NSURI.get());

        StaxUtil.writeStartElement(writer, null, attributeValue.getElementName(), attributeValue.getXmlns());
        StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "xmlns",
                attributeValue.getXmlns());
        StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "code", attributeValue.getCode());
        StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "codeSystem",
                attributeValue.getCodeSystem());
        StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "codeSystemName",
                attributeValue.getCodeSystemName());
        StaxUtil.writeAttribute(writer, null, JBossSAMLURIConstants.XSI_NSURI.get(), "displayName",
                attributeValue.getDisplayName());
        StaxUtil.writeNameSpace(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get());
        StaxUtil.writeAttribute(writer, JBossSAMLURIConstants.XSI_PREFIX.get(), JBossSAMLURIConstants.XSI_NSURI.get(),
                "type", attributeValue.getType());
        StaxUtil.writeEndElement(writer);

        StaxUtil.writeEndElement(writer);
    }

}
