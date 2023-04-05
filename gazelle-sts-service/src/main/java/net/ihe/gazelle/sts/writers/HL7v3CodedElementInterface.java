package net.ihe.gazelle.sts.writers;

/**
 * Created by cel on 02/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public interface HL7v3CodedElementInterface {

    /**
     * <p>getElementName.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getElementName();

    /**
     * <p>getCode.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCode();

    /**
     * <p>getCodeSystem.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCodeSystem();

    /**
     * <p>getCodeSystemName.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getCodeSystemName();

    /**
     * <p>getDisplayName.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getDisplayName();

    /**
     * <p>getXmlns.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getXmlns();

    /**
     * <p>getType.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getType();

}
