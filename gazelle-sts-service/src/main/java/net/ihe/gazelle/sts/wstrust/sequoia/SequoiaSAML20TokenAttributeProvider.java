package net.ihe.gazelle.sts.wstrust.sequoia;

import net.ihe.gazelle.sts.config.AssertionProperties;
import net.ihe.gazelle.sts.config.SequoiaAssertionProperties;
import net.ihe.gazelle.sts.wstrust.ihe.IHESAML20TokenAttributeProvider;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;

/**
 * Created by cel on 08/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class SequoiaSAML20TokenAttributeProvider extends IHESAML20TokenAttributeProvider {

    /** {@inheritDoc} */
    @Override
    protected AttributeType getHomeCommunityIdAttribute(String attributeValue) {
        return getAttribute("urn:nhin:names:saml:homeCommunityId", HOMECOMMUNITYID_FRIENDLYNAME,
                NAMEFORMAT_URI, attributeValue);
    }

    /** {@inheritDoc} */
    @Override
    protected AssertionProperties provideAssertionProperties() {
        return new SequoiaAssertionProperties();
    }

}
