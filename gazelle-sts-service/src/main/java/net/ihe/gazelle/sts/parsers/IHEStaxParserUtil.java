package net.ihe.gazelle.sts.parsers;

import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxParserUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stax.StAXSource;

/**
 * Created by cel on 13/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHEStaxParserUtil extends StaxParserUtil {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /**
     * {@inheritDoc}
     *
     * Given that the {@code XMLEventReader} is in {@code XMLStreamConstants.START_ELEMENT} mode, we parse into a DOM
     * Element
     */
    public static Element getDOMElement(XMLEventReader xmlEventReader) throws ParsingException {
        Transformer transformer = null;

        final String JDK_TRANSFORMER_PROPERTY = "picketlink.jdk.transformer";

        boolean useJDKTransformer = Boolean.parseBoolean(
                SecurityActions.getSystemProperty(JDK_TRANSFORMER_PROPERTY, "false"));


        try {
            if (useJDKTransformer) {
                transformer = IHETransformerUtil.getTransformer();
            } else {
                transformer = IHETransformerUtil.getStaxSourceToDomResultTransformer();
            }

            Document resultDocument = DocumentUtil.createDocument();
            DOMResult domResult = new DOMResult(resultDocument);

            Source source = new StAXSource(xmlEventReader);

            IHETransformerUtil.transform(transformer, source, domResult);

            Document doc = (Document) domResult.getNode();
            return doc.getDocumentElement();
        } catch (ConfigurationException e) {
            throw logger.parserException(e);
        } catch (XMLStreamException e) {
            throw logger.parserException(e);
        }
    }

}
