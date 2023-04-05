package net.ihe.gazelle.sts.saml;

import net.ihe.gazelle.sts.parsers.IHESAMLParser;
import net.ihe.gazelle.sts.writers.IHESAMLAssertionWriter;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxUtil;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Created by cel on 09/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHESAMLUtil extends SAMLUtil {

    private static final Logger LOG = LoggerFactory.getLogger(IHESAMLUtil.class);

    /**
     * <p>
     * Utility method that marshals the specified {@code AssertionType} object into an {@code Element} instance.
     * </p>
     *
     * @param assertion an {@code AssertionType} object representing the SAML assertion to be marshaled.
     * @return a reference to the {@code Element} that contains the marshaled SAML assertion.
     * @throws org.picketlink.common.exceptions.ProcessingException if an error occurs while marshaling the assertion.
     * @throws org.picketlink.common.exceptions.ConfigurationException if any.
     * @throws org.picketlink.common.exceptions.ParsingException if any.
     */
    public static Element toElement(AssertionType assertion) throws ProcessingException, ConfigurationException,
            ParsingException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        IHESAMLAssertionWriter writer = new IHESAMLAssertionWriter(StaxUtil.getXMLStreamWriter(baos));
        writer.write(assertion);

        byte[] assertionBytes = baos.toByteArray();
        ByteArrayInputStream bis = new ByteArrayInputStream(assertionBytes);
        Document document = DocumentUtil.getDocument(bis);

        return document.getDocumentElement();
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Utility method that unmarshals the specified {@code Element} into an {@code AssertionType} instance.
     * </p>
     */
    public static AssertionType fromElement(Element assertionElement)
            throws ProcessingException, ConfigurationException,
            ParsingException {
        IHESAMLParser iheSamlParser = new IHESAMLParser();

        JAXPValidationUtil.checkSchemaValidation(assertionElement);
        return (AssertionType) iheSamlParser.parse(DocumentUtil.getNodeAsStream(assertionElement));
    }

}
