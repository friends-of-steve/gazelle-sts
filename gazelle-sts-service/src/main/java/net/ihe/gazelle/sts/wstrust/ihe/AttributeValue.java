/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;

/**
 */

@XmlRootElement(name = "AttributeValue")
@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement()
public class AttributeValue {

    @XmlAttribute(name="type")
    private String mType;
    @XmlAttribute(name="xsi")
    private String mXsi;

    @XmlValue()
    private String value;

    public AttributeValue() {}

    public String getType() {
        return mType;
    }

    public void setType(String type) {
        this.mType = type;
    }


    public String getXsi() {
        return mXsi;
    }

    public void setXsi(String xsi) {
        this.mXsi = xsi;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

}
