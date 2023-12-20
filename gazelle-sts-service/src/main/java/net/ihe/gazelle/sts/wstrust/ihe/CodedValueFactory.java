/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import java.util.HashMap;

/**
 */
public class CodedValueFactory {

    private HashMap<String, CodedValue> codedValueMap = null;
    private HashMap<String, String> supportedCodedValues = null;

    public CodedValueFactory() {

    }

    public CodedValueFactory(HashMap<String, CodedValue> codedValueMap) {
        this.codedValueMap = codedValueMap;
    }

    public CodedValue getCodedValue(String id) {
        if (codedValueMap == null) {
            populateMap();
        }
        return codedValueMap.get(id);
    }

    public boolean isSupportedCodedValue(String code, String codingSystemUID) {
        if (supportedCodedValues == null) {
            populateSupportedCodedValues();
        }
        if (! supportedCodedValues.containsKey(code)) {
            return false;
        }
        String uid = supportedCodedValues.get(code);
        if (! codingSystemUID.equals(uid)) {
            return false;
        }
        return true;
    }

    private void populateSupportedCodedValues() {
        if (supportedCodedValues == null) {
            supportedCodedValues = new HashMap<>();
        }

        supportedCodedValues.put("TREATMENT",    "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("PAYMENT",      "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("OPERATIONS",   "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("REQUEST",      "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("COVERAGE",     "2.16.840.1.113883.3.7204.1.5.2.1");

        // Added 2023.11.20 to support QHIN 1.1
        supportedCodedValues.put("T-TRTMNT",     "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("T-PYMNT",      "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("T-HCO",        "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("T-PH",         "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("T-IAS",        "2.16.840.1.113883.3.7204.1.5.2.1");
        supportedCodedValues.put("T-GOVDTRM",    "2.16.840.1.113883.3.7204.1.5.2.1");
        // End Add 2023.11.20
    }

    private void populateMap() {
        if (codedValueMap == null) {
            codedValueMap = new HashMap<>();

            codedValueMap.put("TREATMENT",    new CodedValue("TREATMENT",   "TREATMENT",    "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Treatment"));
            codedValueMap.put("PAYMENT",      new CodedValue("PAYMENT",     "PAYMENT",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Payment"));
            codedValueMap.put("OPERATIONS",   new CodedValue("OPERATIONS",  "OPERATIONS",   "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Health Care Operations"));
            codedValueMap.put("PUBLICHEALTH", new CodedValue("PUBLICHEALTH","PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Public Health"));
            codedValueMap.put("REQUEST",      new CodedValue("REQUEST",     "REQUEST",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Individual Access Services"));
            codedValueMap.put("COVERAGE",     new CodedValue("COVERAGE",    "COVERAGE",     "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Government Benefits Determination"));

        // Added 2023.11.20 to support QHIN 1.1
            codedValueMap.put("T-TRTMNT",     new CodedValue("T-TRTMNT",    "T-TRTMNT",     "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Treatment"));
            codedValueMap.put("T-PYMNT",      new CodedValue("T-PYMNT",     "T-PYMNT",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Payment"));
            codedValueMap.put("T-HCO",        new CodedValue("T-HCO",       "T-HCO",        "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Health Care Operations"));
            codedValueMap.put("T-PH",         new CodedValue("T-PH",        "T-PH",         "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Public Health"));
            codedValueMap.put("T-IAS",        new CodedValue("T-IAS",       "T-IAS",        "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Individual Access Services"));
            codedValueMap.put("T-GOVDTRM",    new CodedValue("T-GOVDTRM",   "T-GOVDTRM",    "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Government Benefits Determination"));


        // End Add 2023.11.20

            // Code value is OK, but the coding system UID is wrong.
            codedValueMap.put("TREATMENTOID",    new CodedValue("TREATMENT",   "TREATMENT",    "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Treatment"));
            codedValueMap.put("PAYMENTOID",      new CodedValue("PAYMENT",     "PAYMENT",      "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Payment"));
            codedValueMap.put("OPERATIONSOID",   new CodedValue("OPERATIONS",  "OPERATIONS",   "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Health Care Operations"));
            codedValueMap.put("PUBLICHEALTHOID", new CodedValue("PUBLICHEALTH","PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Public Health"));
            codedValueMap.put("REQUESTOID",      new CodedValue("REQUEST",     "REQUEST",      "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Individual Access Services"));
            codedValueMap.put("COVERAGEOID",     new CodedValue("COVERAGE",    "COVERAGE",     "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Government Benefits Determination"));


            // Code value is OK, but the coding system UID is wrong.
            // Added 2023.12.13 to support QTF 1.1 negative testing
            codedValueMap.put("T-TRTMNT-OID",    new CodedValue("T-TRTMNT",   "T-TRTMNT",  "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Treatment"));
            codedValueMap.put("T-PYMNT-OID",     new CodedValue("T-PYMNT",    "T-PYMNT",   "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Payment"));
            codedValueMap.put("T-HCO-OID",       new CodedValue("T-HCO",      "T-HCO",     "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Health Care Operations"));
            codedValueMap.put("T-PH-OID",        new CodedValue("T-PH",       "T-PH",      "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Public Health"));
            codedValueMap.put("T-IAS-OID",       new CodedValue("T-IAS",      "T-IAS",     "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Individual Access Services"));
            codedValueMap.put("T-GOVDTRM-OID",   new CodedValue("T-GOVDTRM",  "T-GOVDTRM", "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Government Benefits Determination"));
            // End 2023.12.13

            // Correct coding system, but a code that does not exist
            codedValueMap.put("REASSURANCE",      new CodedValue("REASSURANCE",      "REASSURANCE", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Text"));
            // TREATMENT code from NHIN coding system
            codedValueMap.put("LEGACYTREATMENT",  new CodedValue("LEGACYTREATMENT",  "TREATMENT",   "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Legacy NHIN POU Treatment"));

            // This is a case where the proper coded value is used. There are other parts of the SAML assertions
            // that are tweaked to generate an error condition.
            codedValueMap.put("REQUESTATTRS",     new CodedValue("REQUESTATTRS",   "REQUEST",    "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Individual Access Services"));
            // Added 2023.12.13 to support QTF 1.1 negative testing
            codedValueMap.put("T-IAS-ATTRS",     new CodedValue("T-IAS-ATTRS",     "T-IAS",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Individual Access Services"));
            // End 2023.12.13
        }
    }
}
