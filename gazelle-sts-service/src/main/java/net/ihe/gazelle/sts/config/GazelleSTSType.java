package net.ihe.gazelle.sts.config;


import org.picketlink.config.federation.STSType;

/**
 * Created by cel on 18/04/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class GazelleSTSType extends STSType {

    IssuerTrustValidation issuerTrustValidation;

    public IssuerTrustValidation getIssuerTrustValidation() {
        return issuerTrustValidation;
    }

    public void setIssuerTrustValidation(IssuerTrustValidation issuerTrustValidation) {
        this.issuerTrustValidation = issuerTrustValidation;
    }
}
