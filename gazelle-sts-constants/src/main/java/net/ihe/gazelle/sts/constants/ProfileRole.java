package net.ihe.gazelle.sts.constants;

/**
 * <p>List of allowed roles for Gazelle STS. If modified, then WEB-INF/web.xml of gazelle-sts-war application must
 * updated accordingly.</p>
 * Created by cel on 14/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public enum ProfileRole {

    USER("user"),
    PROVIDER("provider");

    private final String role;

    private ProfileRole(String role) {
        this.role = role;
    }

    /**
     * <p>Getter for the field <code>role</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getRole() {
        return role;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return getRole();
    }

}
