package net.ihe.gazelle.wstrust.policy;

import javax.xml.bind.annotation.XmlRegistry;

@XmlRegistry
/**
 * <p>ObjectFactory class.</p>
 *
 * @author cel
 * @version $Id: $Id
 */
public class ObjectFactory {


    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: generated
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link net.ihe.gazelle.wstrust.policy.AppliesToType}
     *
     * @return a {@link net.ihe.gazelle.wstrust.policy.AppliesToType} object.
     */
    public AppliesToType createAppliesToType() {
        return new AppliesToType();
    }


}
