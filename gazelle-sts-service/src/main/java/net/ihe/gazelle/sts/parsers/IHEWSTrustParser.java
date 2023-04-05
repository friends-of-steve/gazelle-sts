package net.ihe.gazelle.sts.parsers;

import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenCollectionParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenResponseCollectionParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenResponseParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustParser;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

/**
 * Created by cel on 12/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHEWSTrustParser extends WSTrustParser {

    /** {@inheritDoc} */
    @Override
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
        while (xmlEventReader.hasNext()) {
            XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);

            if (xmlEvent instanceof StartElement) {
                StartElement startElement = (StartElement) xmlEvent;

                String elementName = StaxParserUtil.getStartElementName(startElement);
                if (elementName.equalsIgnoreCase(WSTrustConstants.RST_COLLECTION)) {
                    WSTRequestSecurityTokenCollectionParser wstrcoll = new WSTRequestSecurityTokenCollectionParser();
                    return wstrcoll.parse(xmlEventReader);
                } else if (elementName.equalsIgnoreCase(WSTrustConstants.RST)) {
                    IHEWSTRequestSecurityTokenParser wst = new IHEWSTRequestSecurityTokenParser();
                    return wst.parse(xmlEventReader);
                } else if (elementName.equalsIgnoreCase(WSTrustConstants.RSTR_COLLECTION)) {
                    WSTRequestSecurityTokenResponseCollectionParser wstrcoll = new WSTRequestSecurityTokenResponseCollectionParser();
                    return wstrcoll.parse(xmlEventReader);
                } else if (elementName.equalsIgnoreCase(WSTrustConstants.RSTR)) {
                    WSTRequestSecurityTokenResponseParser wst = new WSTRequestSecurityTokenResponseParser();
                    return wst.parse(xmlEventReader);
                }
                throw logger.parserFailed(elementName);
            } else {
                StaxParserUtil.getNextEvent(xmlEventReader);
            }
        }
        throw logger.parserFailed(WSTrustConstants.BASE_NAMESPACE);
    }

    /** {@inheritDoc} */
    public boolean supports(QName qname) {
        return WSTrustConstants.BASE_NAMESPACE.equals(qname.getNamespaceURI());
    }
}
