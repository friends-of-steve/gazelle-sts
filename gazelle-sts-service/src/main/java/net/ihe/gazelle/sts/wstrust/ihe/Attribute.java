/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;
/**
 */

@XmlRootElement(name = "Attribute")
@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement()
public class Attribute {

    @XmlAttribute(name="FriendlyName")
    private String mFriendlyName;
    @XmlAttribute(name="Name")
    private String mName;
    @XmlAttribute(name="NameFormat")
    private String mNameFormat;

    @XmlElement(name="AttributeValue")
    private AttributeValue mAttributeValue;

    public Attribute() {}

    public String getFriendlyName() {
        return mFriendlyName;
    }
    public void setFriendlyName(String friendlyName) {
        mFriendlyName = friendlyName;
    }

    public String getName() {
        return mName;
    }
    public void setName(String name) {
        mName = name;
    }

    public String getNameFormat() {
        return mNameFormat;
    }
    public void setNameFormat(String nameFormat) {
        mNameFormat = nameFormat;
    }

    public AttributeValue getAttributeValue() {
        return mAttributeValue;
    }
    public void setAttributeValue(AttributeValue attributeValue) {
        mAttributeValue = attributeValue;
    }
}
