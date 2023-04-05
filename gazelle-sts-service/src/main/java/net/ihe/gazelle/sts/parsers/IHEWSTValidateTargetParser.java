package net.ihe.gazelle.sts.parsers;

import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.parsers.ParserNamespaceSupport;
import org.picketlink.identity.federation.core.parsers.wst.WSTValidateTargetParser;
import org.picketlink.identity.federation.ws.trust.ValidateTargetType;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

/**
 * Created by cel on 13/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHEWSTValidateTargetParser extends WSTValidateTargetParser {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /** {@inheritDoc} */
    @Override
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {
        ValidateTargetType validateTargetType = new ValidateTargetType();
        StartElement startElement = IHEStaxParserUtil.peekNextStartElement(xmlEventReader);
        // null start element indicates that the token to be validated hasn't been specified.
        if (startElement == null) {
            throw logger.parserUnableParsingNullToken();
        }

        // this is an unknown type - parse using the transformer.
        try {
            validateTargetType.add(IHEStaxParserUtil.getDOMElement(xmlEventReader));
        } catch (Exception e) {
            throw logger.parserError(e);
        }

        return validateTargetType;
    }

}
