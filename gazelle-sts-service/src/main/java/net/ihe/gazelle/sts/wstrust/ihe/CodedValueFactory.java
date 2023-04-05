/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import java.util.HashMap;

/**
 */
public class CodedValueFactory {

    private HashMap<String, CodedValue> codedValueMap = null;

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

    private void populateMap() {
        if (codedValueMap == null) {
            codedValueMap = new HashMap<>();

            codedValueMap.put("TREATMENT",    new CodedValue("TREATMENT",   "TREATMENT",    "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Treatment"));
            codedValueMap.put("PAYMENT",      new CodedValue("PAYMENT",     "PAYMENT",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Payment"));
            codedValueMap.put("OPERATIONS",   new CodedValue("OPERATIONS",  "OPERATIONS",   "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Health Care Operations"));
            codedValueMap.put("PUBLICHEALTH", new CodedValue("PUBLICHEALTH","PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Public Health"));
            codedValueMap.put("REQUEST",      new CodedValue("REQUEST",     "REQUEST",      "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Individual Access Services"));
            codedValueMap.put("COVERAGE",     new CodedValue("COVERAGE",    "COVERAGE",     "2.16.840.1.113883.3.7204.1.5.2.1","RCE-purpose","Government Benefits Determination"));

            // Code value is OK, but the coding system UID is wrong.
            codedValueMap.put("TREATMENT-OID",    new CodedValue("TREATMENT",   "TREATMENT",    "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Treatment"));
            codedValueMap.put("PAYMENT-OID",      new CodedValue("PAYMENT",     "PAYMENT",      "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Payment"));
            codedValueMap.put("OPERATIONS-OID",   new CodedValue("OPERATIONS",  "OPERATIONS",   "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Health Care Operations"));
            codedValueMap.put("PUBLICHEALTH-OID", new CodedValue("PUBLICHEALTH","PUBLICHEALTH", "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Public Health"));
            codedValueMap.put("REQUEST-OID",      new CodedValue("REQUEST",     "REQUEST",      "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Individual Access Services"));
            codedValueMap.put("COVERAGE-OID",     new CodedValue("COVERAGE",    "COVERAGE",     "2.16.840.1.113883.3.7204.1.5.2.199","QHIN Exchange Purpose","Government Benefits Determination"));

            // Correct coding system, but a code that does not exist
            codedValueMap.put("REASSURANCE",      new CodedValue("REASSURANCE",      "REASSURANCE", "2.16.840.1.113883.3.7204.1.5.2.1", "RCE-purpose", "Text"));
            // TREATMENT code from NHIN coding system
            codedValueMap.put("LEGACY-TREATMENT",  new CodedValue("LEGACY-TREATMENT", "TREATMENT",  "2.16.840.1.113883.3.18.7.1", "nhin-purpose", "Legacy NHIN POU Treatment"));
        }
    }
}
