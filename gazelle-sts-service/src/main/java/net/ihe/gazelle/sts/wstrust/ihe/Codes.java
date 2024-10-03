/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;
import java.util.List;

/**
 */

@XmlRootElement(name="codes")
@XmlAccessorType(XmlAccessType.FIELD)
public class Codes {

    @XmlElement(name="codedValue")
    private List<CodedValue> mCodedValues;

    public Codes() {}

    public void setCodedValues(List<CodedValue> codedValues) {
        this.mCodedValues = codedValues;
    }

    public List<CodedValue> getCodedValues() {
        return this.mCodedValues;
    }

}
