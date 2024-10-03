/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import javax.xml.bind.annotation.*;
/**
 */

@XmlRootElement(name = "CodedValue")
@XmlAccessorType(XmlAccessType.FIELD)
//@XmlRootElement()
public class CodedValue {

    private String id;
//    @XmlAttribute(name = "code")
    private String code;
//    @XmlAttribute(name = "codingSystemUID")
    private String codingSystemUID;
//    @XmlAttribute(name = "codingSystemName")
    private String codingSystemName;
//    @XmlAttribute(name = "displayName")
    private String displayName;

    public CodedValue() {}

    public CodedValue(String id, String code, String codingSystemUID, String codingSystemName, String displayName) {
        this.id = id;
        this.code = code;
        this.codingSystemUID = codingSystemUID;
        this.codingSystemName = codingSystemName;
        this.displayName = displayName;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getCodingSystemUID() {
        return codingSystemUID;
    }

    public void setCodingSystemUID(String codingSystemUID) {
        this.codingSystemUID = codingSystemUID;
    }

    public String getCodingSystemName() {
        return codingSystemName;
    }

    public void setCodingSystemName(String codingSystemName) {
        this.codingSystemName = codingSystemName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}
