/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.util.*;

/**
 */
public class CodedValueFactory {
    private static final Logger LOG = LoggerFactory.getLogger(CodedValueFactory.class);

    // This is a map from an identifier to a coded value
    // By practice, the identifier can be similar to the coded value
    // or slightly different. This allows us to use different identifiers
    // to map to the same coded value. This is useful to support
    // testing in different projects where each project might be best
    // served by having a different identifier for what would be the same
    // coded value
    private Map<String, CodedValue> allCodes = null;

    // Map of codes that are recognized for inbound transactions
    // The values in the set are "CODE:OID" as in
    // "TREATMENT:2.16.840.1.113883.3.7204.1.5.2.1"
    //private Map<String, String> inboundSupportedCodedValues = null;
    private Set<String> inboundSupportedCodedValues = null;

    public CodedValueFactory() {

    }

    public CodedValue getCodedValue(String id) {
        //System.out.println("Get Coded Value: " + id);
        LOG.debug("CodedValueFactory::getCodedValue key = " + id);
        if (allCodes == null) {
            populateAllCodes();
        }
        CodedValue codedValue = allCodes.get(id);
        if (codedValue == null) {
            LOG.error("CodedValueFactory::getCodedValue Unable to find coded value for key = " + id);
            LOG.error("CodedValueFactory::getCodedValue Look for the map of values in /opt/sts/allCodes.xml");
        }
        return codedValue;
    }

    public boolean isSupportedCodedValue(String code, String codingSystemUID) {
        if (inboundSupportedCodedValues == null) {
            populateInboundSupportedCodedValues();
        }
        String key = code + ":" + codingSystemUID;
        if (inboundSupportedCodedValues.contains(key)) {
            return true;
        } else {
            return false;
        }
    }

    private void populateInboundSupportedCodedValues() {
        if (inboundSupportedCodedValues == null) {
            inboundSupportedCodedValues = convertCodeListToSet(readCodeValueMap("/opt/sts/inboundSupportedCodes.xml"));
            if (inboundSupportedCodedValues != null) {
                // This should be executed one time when this method reads the supported set of inbound codes.
                // Log each coded value for diagnostic work that will happen much later.
                LOG.error("Set of inbound supported codes will now be logged at ERROR level to ensure they are visible.");
                Iterator<String> it = inboundSupportedCodedValues.iterator();
                while (it.hasNext()) {
                    String code = it.next();
                    LOG.error(code);
                }
            } else {
                LOG.error("ERROR: Did not find or read /opt/sts/inboundSupportedCodes.xml. Only default inbound code values will be supported");
                inboundSupportedCodedValues = new HashSet<>();
            }
        }
    }

    private void populateAllCodes() {
        if (allCodes == null) {
            LOG.debug("CodedValueFactory::populateAllCodes: read from hardcoded path /opt/sts/allCodes.xml");
            allCodes = convertCodeListToFullMap(readCodeValueMap("/opt/sts/allCodes.xml"));
            if (allCodes == null) {
                LOG.warn("ERROR: Did not find or read /opt/sts/allCodes.xml. Only default code values for output will be supported");

                allCodes = new HashMap<>();
            }
        }
    }

    private Codes readCodeValueMap(final String path) {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(Codes.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            Codes codes = (Codes) unmarshaller.unmarshal(new File(path));
            LOG.debug("Successfully read codes from: " + path);
            return codes;
        } catch (Exception e) {
            LOG.error("Unable to read codes from: " + path);
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, CodedValue> convertCodeListToFullMap(Codes codes) {
        HashMap map = new HashMap<>();

        Iterator<CodedValue> it = codes.getCodedValues().listIterator();
        while (it.hasNext()) {
            CodedValue c = it.next();
            map.put(c.getId(), c);
            System.out.println("Code ID: " + c.getId());
        }
        return map;
    }

    private Set<String> convertCodeListToSet(Codes codes) {
        HashSet<String> set = new HashSet<>();

        Iterator<CodedValue> it = codes.getCodedValues().listIterator();
        while (it.hasNext()) {
            CodedValue c = it.next();
            set.add(c.getCode() + ":" + c.getCodingSystemUID());
        }
        return set;
    }
}
