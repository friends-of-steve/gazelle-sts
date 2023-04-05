package net.ihe.gazelle.wstrust.secext;

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

    private final static QName _EmbeddedTypeAny_QNAME = new QName("", ":1");
    private final static QName _SecurityTokenReferenceTypeAny_QNAME = new QName("", ":1");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: generated
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link net.ihe.gazelle.wstrust.secext.KeyIdentifier}
     *
     * @return a {@link net.ihe.gazelle.wstrust.secext.KeyIdentifier} object.
     */
    public KeyIdentifier createKeyIdentifier() {
        return new KeyIdentifier();
    }


}
