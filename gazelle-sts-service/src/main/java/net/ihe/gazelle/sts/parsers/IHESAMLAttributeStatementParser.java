package net.ihe.gazelle.sts.parsers;

import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.identity.federation.core.parsers.util.SAMLParserUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Created by cel on 09/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHESAMLAttributeStatementParser {

    private static final Logger LOG = LoggerFactory.getLogger(IHESAMLAttributeStatementParser.class);

    /**
     * Parse an {@code AttributeStatementType}
     *
     * @param xmlEventReader a {@link javax.xml.stream.XMLEventReader} object.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType} object.
     */
    public static AttributeStatementType parseAttributeStatement(XMLEventReader xmlEventReader)
            throws ParsingException {
        AttributeStatementType attributeStatementType = new AttributeStatementType();

        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        String ATTRIBSTATEMT = JBossSAMLConstants.ATTRIBUTE_STATEMENT.get();
        StaxParserUtil.validate(startElement, ATTRIBSTATEMT);

        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent instanceof EndElement) {
                EndElement endElement = StaxParserUtil.getNextEndElement(xmlEventReader);
                StaxParserUtil.validate(endElement, JBossSAMLConstants.ATTRIBUTE_STATEMENT.get());
                break;
            }
            // Get the next start element
            startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
            String tag = startElement.getName().getLocalPart();

            // If we are on an "AttributeValue" tag, we break the while because we cannot add information about Role
            // and PurposeOfUse in attributeStatementType
            Attribute type = startElement
                    .getAttributeByName(new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xsi"));
            String localPart = startElement.getName().getLocalPart();
            if (type == null && localPart == "AttributeValue") {
                break;
            }

            if (JBossSAMLConstants.ATTRIBUTE.get().equals(tag)) {
                AttributeType attribute = parseAttribute(xmlEventReader);
                attributeStatementType.addAttribute(new AttributeStatementType.ASTChoiceType(attribute));
            } else {
                throw new ParsingException(
                        "PL00062: Parser : Unknown tag: " + tag + " at " + startElement.getLocation());
            }
        }
        return attributeStatementType;
    }

    /**
     * Parse an {@code AttributeType}
     *
     * @param xmlEventReader a {@link javax.xml.stream.XMLEventReader} object.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    public static AttributeType parseAttribute(XMLEventReader xmlEventReader) throws ParsingException {
        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        StaxParserUtil.validate(startElement, JBossSAMLConstants.ATTRIBUTE.get());
        AttributeType attributeType = null;

        Attribute name = startElement.getAttributeByName(new QName(JBossSAMLConstants.NAME.get()));
        if (name == null) {
            throw new ParsingException("PL00063: Parser: Required attribute missing: Name");
        }
        attributeType = new AttributeType(StaxParserUtil.getAttributeValue(name));

        parseAttributeType(xmlEventReader, startElement, JBossSAMLConstants.ATTRIBUTE.get(), attributeType);

        return attributeType;
    }

    /**
     * Parse an {@code AttributeType}
     *
     * @param xmlEventReader a {@link javax.xml.stream.XMLEventReader} object.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     * @param startElement a {@link javax.xml.stream.events.StartElement} object.
     * @param rootTag a {@link java.lang.String} object.
     * @param attributeType a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    public static void parseAttributeType(XMLEventReader xmlEventReader, StartElement startElement, String rootTag,
                                          AttributeType attributeType) throws ParsingException {
        // Look for X500 Encoding
        QName x500EncodingName = new QName(JBossSAMLURIConstants.X500_NSURI.get(), JBossSAMLConstants.ENCODING.get(),
                JBossSAMLURIConstants.X500_PREFIX.get());
        Attribute x500EncodingAttr = startElement.getAttributeByName(x500EncodingName);

        if (x500EncodingAttr != null) {
            attributeType.getOtherAttributes().put(x500EncodingAttr.getName(),
                    StaxParserUtil.getAttributeValue(x500EncodingAttr));
        }

        Attribute friendlyName = startElement.getAttributeByName(new QName(JBossSAMLConstants.FRIENDLY_NAME.get()));
        if (friendlyName != null) {
            attributeType.setFriendlyName(StaxParserUtil.getAttributeValue(friendlyName));
        }

        Attribute nameFormat = startElement.getAttributeByName(new QName(JBossSAMLConstants.NAME_FORMAT.get()));
        if (nameFormat != null) {
            attributeType.setNameFormat(StaxParserUtil.getAttributeValue(nameFormat));
        }

        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent instanceof EndElement) {
                EndElement end = StaxParserUtil.getNextEndElement(xmlEventReader);
                if (StaxParserUtil.matches(end, rootTag)) {
                    break;
                }
            }
            startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
            if (startElement == null) {
                break;
            }
            String tag = StaxParserUtil.getStartElementName(startElement);

            // If we are on an "AttributeValue" tag, we break the while because we cannot add information about Role and PurposeOfUse
            Attribute type = startElement
                    .getAttributeByName(new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xsi"));
            String localPart = startElement.getName().getLocalPart();
            if (type == null && localPart == "AttributeValue") {
                break;
            }

            if (JBossSAMLConstants.ATTRIBUTE.get().equals(tag)) {
                break;
            }

            if (JBossSAMLConstants.ATTRIBUTE_VALUE.get().equals(tag)) {
                Object attributeValue = parseAttributeValue(xmlEventReader);
                attributeType.addAttributeValue(attributeValue);
            } else {
                throw new ParsingException(
                        "PL00062: Parser : Unknown tag: " + tag + " at " + startElement.getLocation());
            }
        }
    }

    /**
     * Parse Attribute value
     *
     * @param xmlEventReader a {@link javax.xml.stream.XMLEventReader} object.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     * @return a {@link java.lang.Object} object.
     */
    public static Object parseAttributeValue(XMLEventReader xmlEventReader) throws ParsingException {
        StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
        StaxParserUtil.validate(startElement, JBossSAMLConstants.ATTRIBUTE_VALUE.get());

        Attribute type = startElement
                .getAttributeByName(new QName(JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xsi"));

        if (type == null) {
            if (StaxParserUtil.hasTextAhead(xmlEventReader)) {
                return StaxParserUtil.getElementText(xmlEventReader);
            }
            // Else we may have Child Element
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
            if (xmlEvent instanceof StartElement) {
                startElement = (StartElement) xmlEvent;
                String tag = StaxParserUtil.getStartElementName(startElement);
                if (tag.equals(JBossSAMLConstants.NAMEID.get())) {
                    return SAMLParserUtil.parseNameIDType(xmlEventReader);
                }
            } else if (xmlEvent instanceof EndElement) {
                return "";
            }

            throw new RuntimeException(
                    "PL00069: Parser: Type not supported: " + StaxParserUtil.getStartElementName(startElement));
        }

        //      RK Added an additional type check for base64Binary type as calheers is passing this type
        String typeValue = StaxParserUtil.getAttributeValue(type);
        if (typeValue.contains(":string")) {
            return StaxParserUtil.getElementText(xmlEventReader);
        } else if (typeValue.contains(":anyType")) {
            // TODO: for now assume that it is a text value that can be parsed and set as the attribute value
            return StaxParserUtil.getElementText(xmlEventReader);
        } else if (typeValue.contains(":base64Binary")) {
            return StaxParserUtil.getElementText(xmlEventReader);
        } else if (typeValue.contains(":anyURI")) {
            return StaxParserUtil.getElementText(xmlEventReader);
        }

        throw new ParsingException("PL0065: Parser : Unknown xsi:type=" + typeValue);
    }


}
