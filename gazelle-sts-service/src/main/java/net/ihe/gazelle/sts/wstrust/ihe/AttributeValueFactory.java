/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

/**
 */
public class AttributeValueFactory {
    //private static final Logger LOG = LoggerFactory.getLogger(AttributeValueFactory.class);
    private static final PicketLinkLogger LOG = PicketLinkLoggerFactory.getLogger();

    private Map<String, AttributeSet> outboundSAMLAttributes = null;

    public AttributeValueFactory() {

    }

    public AttributeSet getAttributeSet(String key) {
        if (outboundSAMLAttributes == null) {
            populateOutboundSAMLAttributes();

        }
        if (outboundSAMLAttributes != null) {
            AttributeSet staticSet = outboundSAMLAttributes.get(key);
            return CopyAndSubstituteAttributeValues(staticSet);
        } else {
            return null;
        }
    }

    /* TODO: This needs to be fixed. It is used differently for different reasons. Not good */
    /* Look through the elements. If an element has an attribute that points to a file name,
       fill in the value of the element with that file name.
     */
    private AttributeSet CopyAndSubstituteAttributeValues(AttributeSet inputAttributes) {
        if (inputAttributes == null) {
            return inputAttributes;
        } else if (inputAttributes.getListOfAttributes() == null) {
            return inputAttributes;
        }

        AttributeSet outputSet = new AttributeSet();
        Iterator<Attribute> iterator = inputAttributes.getListOfAttributes().iterator();
        while (iterator.hasNext()) {
            // Clone the attribute so that the original remains unchanged.
            // In the 'if' clause below, we will modify the attribute.
            // Next time we come back to this method, we still want the original
            // version of the attribute in the event that the file content was updated.
            Attribute attribute = iterator.next().clone();
            if (attribute.getmFileName() != null) {
                String textValue = readString(attribute.getmFileName());
                AttributeValue av = attribute.getAttributeValue();
                av.setValue(textValue);
                attribute.setAttributeValue(av);
                attribute.setmFileName(null);
            }
            outputSet.addAttribute(attribute);
        }
        return outputSet;
    }

    private String readString(String path) {
        try {
            LOG.error("ReadString: " + path);
            byte[] bytes = Files.readAllBytes(Paths.get(path));
            String str = new String(bytes, StandardCharsets.UTF_8);
            LOG.error(str);
            return str;
        } catch (Exception e) {
            return "STS runtime error, unable to read attribute value from " + path;
        }
    }

    private void populateOutboundSAMLAttributes() {
        if (outboundSAMLAttributes == null) {
            outboundSAMLAttributes = new HashMap<>();
            AttributeMap map = readAttributeMap("/opt/sts/outboundSAMLAttributes.xml");
            List<AttributeSet> attributeSets = map.getListOfAttributeSets();
            Iterator<AttributeSet> it = attributeSets.iterator();
            while (it.hasNext()) {
                AttributeSet s = it.next();
                outboundSAMLAttributes.put(s.getKey(), s);
            }
        }
    }

    private AttributeMap readAttributeMap(final String path) {
        try {

            JAXBContext jaxbContext;
            Unmarshaller unmarshaller;

            jaxbContext = JAXBContext.newInstance(AttributeMap.class);
            unmarshaller = jaxbContext.createUnmarshaller();
            AttributeMap map = (AttributeMap) unmarshaller.unmarshal(new File(path));

            System.out.println(map.getListOfAttributeSets().size());
            List<AttributeSet> list = map.getListOfAttributeSets();
            Iterator<AttributeSet> itX = list.iterator();
            while (itX.hasNext()) {
                AttributeSet attributeSet = itX.next();
                System.out.println(attributeSet.getKey());
                Iterator<Attribute> itY = attributeSet.getListOfAttributes().iterator();
                while (itY.hasNext()) {
                    Attribute attribute = itY.next();
                    System.out.println(attribute.getFriendlyName() + " " + attribute.getAttributeValue().getValue());
                }
            }
            return map;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
