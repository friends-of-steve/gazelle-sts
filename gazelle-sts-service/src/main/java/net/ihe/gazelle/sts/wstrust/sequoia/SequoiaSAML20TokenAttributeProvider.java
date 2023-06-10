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
    /*  2023.06.10
        This class and method was originally added to allow STS to override the default IHE
        behavior/values with values from the Sequoia Project. This method uses a hard-coded
        value for the Name attribute that will be in the <Attribute>.
        We added more configuration to allow the baseline (IHE class) to get the Name value
        at runtime from a properties file.
        Leaving the class here for now. I suspect this Sequoia class and related classes
        will eventually be removed.
     */
    /*
    @Override
    protected AttributeType getHomeCommunityIdAttribute(String attributeName, String attributeValue) {
        return getAttribute("urn:nhin:names:saml:homeCommunityId", HOMECOMMUNITYID_FRIENDLYNAME,
                NAMEFORMAT_URI, attributeValue);
    }
     */

    /** {@inheritDoc} */
    @Override
    protected AssertionProperties provideAssertionProperties() {
        return new SequoiaAssertionProperties();
    }

}
