package net.ihe.gazelle.sts.saml;

import net.ihe.gazelle.sts.writers.HL7v3CodedElementInterface;

/**
 * Created by cel on 02/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public abstract class AbstractHL7v3CodedElement implements HL7v3CodedElementInterface {

    private static final String XMLNS = "urn:hl7-org:v3";
    private static final String TYPE = "CE";
    private String code;
    private String codeSystem;
    private String codeSystemName;
    private String displayName;

    /**
     * <p>Constructor for AbstractHL7v3CodedElement.</p>
     */
    public AbstractHL7v3CodedElement() {
        setCode(null);
        setCodeSystem(null);
        setCodeSystemName(null);
        setDisplayName(null);
    }

    /**
     * <p>Constructor for AbstractHL7v3CodedElement.</p>
     *
     * @param code a {@link java.lang.String} object.
     * @param codeSystem a {@link java.lang.String} object.
     * @param codeSystemName a {@link java.lang.String} object.
     * @param displayName a {@link java.lang.String} object.
     */
    public AbstractHL7v3CodedElement(String code, String codeSystem, String codeSystemName, String displayName) {
        setCode(code);
        setCodeSystem(codeSystem);
        setCodeSystemName(codeSystemName);
        setDisplayName(displayName);
    }

    /**
     * <p>getElementName.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public abstract String getElementName();

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCode() {
        return code;
    }

    /**
     * {@inheritDoc}
     *
     * @param code a {@link java.lang.String} object.
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCodeSystem() {
        return codeSystem;
    }

    /**
     * {@inheritDoc}
     *
     * @param codeSystem a {@link java.lang.String} object.
     */
    public void setCodeSystem(String codeSystem) {
        this.codeSystem = codeSystem;
    }

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCodeSystemName() {
        return codeSystemName;
    }

    /**
     * {@inheritDoc}
     *
     * @param codeSystemName a {@link java.lang.String} object.
     */
    public void setCodeSystemName(String codeSystemName) {
        this.codeSystemName = codeSystemName;
    }

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * {@inheritDoc}
     *
     * @param displayName a {@link java.lang.String} object.
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getXmlns() {
        return XMLNS;
    }

    /**
     * {@inheritDoc}
     *
     * @return a {@link java.lang.String} object.
     */
    public String getType() {
        return TYPE;
    }

}
