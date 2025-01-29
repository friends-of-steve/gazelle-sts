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

    /*
    public CodedValueFactory(HashMap<String, CodedValue> codedValueMap) {
        this.codedValueMap = codedValueMap;
    }
     */

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

/*                inboundSupportedCodedValues.add(   "TREATMENT:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(     "PAYMENT:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(  "OPERATIONS:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add("PUBLICHEALTH:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(     "REQUEST:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(    "COVERAGE:2.16.840.1.113883.3.7204.1.5.2.1");

                // Added 2023.11.20 to support QHIN 1.1
                inboundSupportedCodedValues.add(  "T-TRTMNT:.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(  "T-PYMNT:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(    "T-HCO:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(     "T-PH:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add(    "T-IAS:2.16.840.1.113883.3.7204.1.5.2.1");
                inboundSupportedCodedValues.add("T-GOVDTRM:2.16.840.1.113883.3.7204.1.5.2.1");
                // End Add 2023.11.20

                // Added 2024.09.28 to support eHx ACP
                inboundSupportedCodedValues.add(       "COVERAGE:2.16.840.1.113883.3.18.7.1");
                // End Add 2024.09.28

 */
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
/*
                allCodes.put("TREATMENT", new CodedValue("TREATMENT", "TREATMENT", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Treatment"));
                allCodes.put("PAYMENT", new CodedValue("PAYMENT", "PAYMENT", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Payment"));
                allCodes.put("OPERATIONS", new CodedValue("OPERATIONS", "OPERATIONS", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Health Care Operations"));
                allCodes.put("PUBLICHEALTH", new CodedValue("PUBLICHEALTH", "PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Public Health"));
                allCodes.put("REQUEST", new CodedValue("REQUEST", "REQUEST", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Individual Access Services"));
                allCodes.put("COVERAGE", new CodedValue("COVERAGE", "COVERAGE", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Government Benefits Determination"));

                // Added 2023.11.20 to support QHIN 1.1
                allCodes.put("T-TRTMNT", new CodedValue("T-TRTMNT", "T-TRTMNT", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Treatment"));
                allCodes.put("T-PYMNT", new CodedValue("T-PYMNT", "T-PYMNT", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Payment"));
                allCodes.put("T-HCO", new CodedValue("T-HCO", "T-HCO", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Health Care Operations"));
                allCodes.put("T-PH", new CodedValue("T-PH", "T-PH", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Public Health"));
                allCodes.put("T-IAS", new CodedValue("T-IAS", "T-IAS", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Individual Access Services"));
                allCodes.put("T-GOVDTRM", new CodedValue("T-GOVDTRM", "T-GOVDTRM", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Government Benefits Determination"));
                // End Add 2023.11.20

                // Code value is OK, but the coding system UID is wrong.
                allCodes.put("TREATMENTOID", new CodedValue("TREATMENT", "TREATMENT", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Treatment"));
                allCodes.put("PAYMENTOID", new CodedValue("PAYMENT", "PAYMENT", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Payment"));
                allCodes.put("OPERATIONSOID", new CodedValue("OPERATIONS", "OPERATIONS", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Health Care Operations"));
                allCodes.put("PUBLICHEALTHOID", new CodedValue("PUBLICHEALTH", "PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Public Health"));
                allCodes.put("REQUESTOID", new CodedValue("REQUEST", "REQUEST", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Individual Access Services"));
                allCodes.put("COVERAGEOID", new CodedValue("COVERAGE", "COVERAGE", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Government Benefits Determination"));

                // Code value is OK, but the coding system UID is wrong.
                // Added 2023.12.13 to support QTF 1.1 negative testing
                allCodes.put("T-TRTMNT-OID", new CodedValue("T-TRTMNT", "T-TRTMNT", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Treatment"));
                allCodes.put("T-PYMNT-OID", new CodedValue("T-PYMNT", "T-PYMNT", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Payment"));
                allCodes.put("T-HCO-OID", new CodedValue("T-HCO", "T-HCO", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Health Care Operations"));
                allCodes.put("T-PH-OID", new CodedValue("T-PH", "T-PH", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Public Health"));
                allCodes.put("T-IAS-OID", new CodedValue("T-IAS", "T-IAS", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Individual Access Services"));
                allCodes.put("T-GOVDTRM-OID", new CodedValue("T-GOVDTRM", "T-GOVDTRM", "2.16.840.1.113883.3.7204.1.5.2.199", "QHIN Exchange Purpose", "Government Benefits Determination"));
                // End 2023.12.13

                // Correct coding system, but a code that does not exist
                allCodes.put("REASSURANCE", new CodedValue("REASSURANCE", "REASSURANCE", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Text"));
                // TREATMENT code from NHIN coding system
                allCodes.put("LEGACYTREATMENT", new CodedValue("LEGACYTREATMENT", "TREATMENT", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Legacy NHIN POU Treatment"));

                // This is a case where the proper coded value is used. There are other parts of the SAML assertions
                // that are tweaked to generate an error condition.
                allCodes.put("REQUESTATTRS", new CodedValue("REQUESTATTRS", "REQUEST", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Individual Access Services"));
                // Added 2023.12.13 to support QTF 1.1 negative testing
                allCodes.put("T-IAS-ATTRS", new CodedValue("T-IAS-ATTRS", "T-IAS", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Individual Access Services"));
                // End 2023.12.13

                // Added 2024.09.28 to support eHx ACP
                allCodes.put("ACP-Ernser",   new CodedValue("ACP-Ernser",   "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                allCodes.put("ACP-Orn",      new CodedValue("ACP-Orn",      "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                allCodes.put("ACP-Predovic", new CodedValue("ACP-Predovic", "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                allCodes.put("ACP-Quigley",  new CodedValue("ACP-Quigley",  "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                allCodes.put("ACP-Simonis",  new CodedValue("ACP-Simonis",  "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                allCodes.put("ACP-West",     new CodedValue("ACP-West",     "COVERAGE", "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Disclosures for insurance or disability coverage determination"));
                // End add 2024.09.28

 */
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
