/*
 */
package net.ihe.gazelle.sts.wstrust.ihe;

/**
 */
public class CodedValue {

    private String id;
    private String code;
    private String codingSystemUID;
    private String codingSystemName;
    private String displayName;

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
