/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.util.*;

/**
 */
public class AttributeValueFactory {

    private Map<String, AttributeSet> outboundSAMLAttributes = null;

    public AttributeValueFactory() {

    }

    public AttributeSet getAttributeSet(String key) {
        if (outboundSAMLAttributes == null) {
            populateOutboundSAMLAttributes();

        }
        if (outboundSAMLAttributes != null) {
            return outboundSAMLAttributes.get(key);
        } else {
            return null;
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
