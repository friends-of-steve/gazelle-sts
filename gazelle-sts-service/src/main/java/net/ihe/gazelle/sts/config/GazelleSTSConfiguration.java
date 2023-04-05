package net.ihe.gazelle.sts.config;

import net.ihe.gazelle.pki.ws.CertificateValidator;
import net.ihe.gazelle.pki.ws.CertificateValidatorException;
import org.picketlink.identity.federation.core.wstrust.PicketLinkSTSConfiguration;

/**
 * Created by cel on 18/04/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class GazelleSTSConfiguration extends PicketLinkSTSConfiguration {

    private GazelleSTSType delegate;

    /**
     * <p>Constructor for GazelleSTSConfiguration.</p>
     *
     * @param config a {@link net.ihe.gazelle.sts.config.GazelleSTSType} object.
     */
    public GazelleSTSConfiguration(GazelleSTSType config) {
        super(config);
        this.delegate = config;
    }

    /**
     * <p>getCertificateValidator.</p>
     *
     * @return a {@link net.ihe.gazelle.pki.ws.CertificateValidator} object.
     * @throws net.ihe.gazelle.pki.ws.CertificateValidatorException if any.
     */
    public CertificateValidator getCertificateValidator() throws Exception {
        return new CertificateValidator(this.delegate.getIssuerTrustValidation().getPKICertificateValidatorEndPoint());
    }

    public Boolean isIssuerTrustValidationEnabled() {
        return delegate.getIssuerTrustValidation().isIssuerTrustValidationEnabled();
    }

}
