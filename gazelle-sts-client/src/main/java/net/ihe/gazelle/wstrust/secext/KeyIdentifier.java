package net.ihe.gazelle.wstrust.secext;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Created by aberge on 27/02/17.
 *
 * @author cel
 * @version $Id: $Id
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyIdentifier", propOrder = {
        "valueType",
        "value"
})
@XmlRootElement(name = "KeyIdentifier")
public class KeyIdentifier {

    @XmlAttribute(name = "ValueType")
    private String valueType;

    @XmlValue
    private String value;
    /**
     * An attribute containing marshalled element node
     */
    @XmlTransient
    private Node _xmlNodePresentation;

    /**
     * <p>Getter for the field <code>valueType</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getValueType() {
        return valueType;
    }

    /**
     * <p>Setter for the field <code>valueType</code>.</p>
     *
     * @param valueType a {@link java.lang.String} object.
     */
    public void setValueType(String valueType) {
        this.valueType = valueType;
    }

    /**
     * <p>Getter for the field <code>value</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getValue() {
        return value;
    }

    /**
     * <p>Setter for the field <code>value</code>.</p>
     *
     * @param value a {@link java.lang.String} object.
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * <p>Getter for the field <code>_xmlNodePresentation</code>.</p>
     *
     * @return a {@link org.w3c.dom.Node} object.
     */
    public Node get_xmlNodePresentation() {
        if (_xmlNodePresentation == null) {
            JAXBContext jc;
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = null;
            Document doc = null;
            try {
                db = dbf.newDocumentBuilder();
                doc = db.newDocument();
            } catch (ParserConfigurationException e1) {
            }
            try {
                jc = JAXBContext.newInstance("net.ihe.gazelle.wstrust.secext");
                Marshaller m = jc.createMarshaller();
                m.marshal(this, doc);
                _xmlNodePresentation = doc.getElementsByTagNameNS(
                        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
                        "KeyIdentifier").item(0);
            } catch (JAXBException e) {
                try {
                    db = dbf.newDocumentBuilder();
                    _xmlNodePresentation = db.newDocument();
                } catch (Exception ee) {
                }
            }
        }
        return _xmlNodePresentation;
    }

    /**
     * <p>Setter for the field <code>_xmlNodePresentation</code>.</p>
     *
     * @param _xmlNodePresentation a {@link org.w3c.dom.Node} object.
     */
    public void set_xmlNodePresentation(Node _xmlNodePresentation) {
        this._xmlNodePresentation = _xmlNodePresentation;
    }
}
