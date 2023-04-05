package net.ihe.gazelle.sts.wstrust.common;

import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAML20TokenAttributeProvider;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;

/**
 * Created by cel on 17/05/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public interface ExtendedSAML20TokenAttributeProvider extends SAML20TokenAttributeProvider {

    /**
     * <p>getAttributeStatement.</p>
     *
     * @param context a {@link org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType} object.
     */
    AttributeStatementType getAttributeStatement(WSTrustRequestContext context) ;

}
