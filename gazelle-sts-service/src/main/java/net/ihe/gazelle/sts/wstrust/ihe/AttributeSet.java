/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;

/**
 */

@XmlRootElement(name = "AttributeSet")
@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement()
public class AttributeSet {

    @XmlAttribute()
    private String key;

    @XmlElement(name="Attribute")
    private ArrayList<Attribute> listOfAttributes;

    public AttributeSet() {}

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public ArrayList<Attribute> getListOfAttributes() {
        return listOfAttributes;
    }

    public void setListOfAttributes(ArrayList<Attribute> listOfAttributes) {
        this.listOfAttributes = listOfAttributes;
    }

    public void addAttribute(Attribute attribute) {
        if (listOfAttributes == null) {
            listOfAttributes = new ArrayList<>();
        }
        listOfAttributes.add(attribute);
    }
}
