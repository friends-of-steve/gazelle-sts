/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;

/**
 */

@XmlRootElement(name = "AttributeMap")
@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement()
public class AttributeMap {

    @XmlElement(name="AttributeSet")
    private ArrayList<AttributeSet> listOfAttributeSets;

    public AttributeMap() {}

    public ArrayList<AttributeSet> getListOfAttributeSets() {
        return listOfAttributeSets;
    }

    public void setListOfAttributeSets(ArrayList<AttributeSet> listOfAttributeSets) {
        this.listOfAttributeSets = listOfAttributeSets;
    }

    public void addAttributeSet(AttributeSet attributeSet) {
        if (listOfAttributeSets == null) {
            listOfAttributeSets = new ArrayList<>();
        }
        listOfAttributeSets.add(attributeSet);
    }
}
