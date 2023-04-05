package net.ihe.gazelle.wstrust.addressing;

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
     * Create an instance of {@link net.ihe.gazelle.wstrust.addressing.EndpointReferenceType}
     *
     * @return a {@link net.ihe.gazelle.wstrust.addressing.EndpointReferenceType} object.
     */
    public EndpointReferenceType createEndpointReferenceType() {
        return new EndpointReferenceType();
    }


}
