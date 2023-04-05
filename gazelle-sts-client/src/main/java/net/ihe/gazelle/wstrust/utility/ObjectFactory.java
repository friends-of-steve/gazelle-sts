package net.ihe.gazelle.wstrust.utility;

import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;

@XmlRegistry
/**
 * <p>ObjectFactory class.</p>
 *
 * @author cel
 * @version $Id: $Id
 */
public class ObjectFactory {

    private final static QName _TimestampTypeAny_QNAME = new QName("", ":3");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: generated
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link net.ihe.gazelle.wstrust.utility.TimestampType}
     *
     * @return a {@link net.ihe.gazelle.wstrust.utility.TimestampType} object.
     */
    public TimestampType createTimestampType() {
        return new TimestampType();
    }


}
