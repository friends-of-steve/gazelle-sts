package net.ihe.gazelle.sts.config;

public class IssuerTrustValidation {

    protected String pkiCertificateValidatorEndPoint;
    protected Boolean issuerTrustValidationEnabled;


    /**
     * <p>getPKICertificateValidatorEndPoint.</p>
     *
     * @return a {@link java.lang.String} object.
     * @throws java.io.IOException if any.
     */
    public String getPKICertificateValidatorEndPoint() throws Exception {
        if (pkiCertificateValidatorEndPoint == null) {
            throw new Exception("Cannot find certificate validator endpoint");
            //this.pkiCertificateValidatorEndPoint = "https://gazelle.ihe.net/gazelle-atna-ejb/CertificateValidatorService/CertificateValidator";
        }
        return pkiCertificateValidatorEndPoint;
    }

    /**
     * <p>setPKICertificateValidatorEndPoint.</p>
     *
     * @param pkiCertificateValidatorEndPoint a {@link java.lang.String} object.
     */
    public void setPKICertificateValidatorEndPoint(String pkiCertificateValidatorEndPoint) {
        this.pkiCertificateValidatorEndPoint = pkiCertificateValidatorEndPoint;
    }

    public Boolean isIssuerTrustValidationEnabled() {
        return issuerTrustValidationEnabled;
    }

    public void setIssuerTrustValidationEnabled(boolean issuerTrustValidationEnabled) {
        this.issuerTrustValidationEnabled = issuerTrustValidationEnabled;
    }

    public void setIssuerTrustValidation(String issuerTrustValidation) {
        if (issuerTrustValidation.equalsIgnoreCase("true") || issuerTrustValidation.equalsIgnoreCase("false")) {
            this.issuerTrustValidationEnabled = Boolean.valueOf(issuerTrustValidation);
        } else {
            this.issuerTrustValidationEnabled = null;
        }
    }

}
