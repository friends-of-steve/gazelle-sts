package net.ihe.gazelle.sts.constants;

/**
 * <p>Gazelle-STS is able to generate several SAML assertion types for testing purpose (valid, expired, unsigned, etc.).
 * In order to communicate to Gazelle STS which assertion profile you require, request must be send using HTTP
 * authentication with a specific credential</p>
 * <p>To know what is the credential for a profile, you can call {@link #getName()} and {@link #getPassword()}</p>
 * <p>Created by cel on 14/06/17.</p>
 *
 * @author cel
 * @version $Id: $Id
 */
public enum AssertionProfile {

    VALID("valid"),
    NOT_YET_VALID("notyetvalid"),
    EXPIRED("expired"),
    UNSIGNED("unsigned"),
    INVALID_SIGNATURE("invalidsignature"),
    MISSING_KEY_INFO("missingkeyinfo"),
    MISSING_KEY_VALUE("missingkeyvalue"),
    MISSING_RSA_KEY_VALUE("missingrsakeyvalue"),
    MISSING_RSA_KEY_MODULUS("missingrsakeymodulus"),
    MISSING_RSA_KEY_EXPONENT("missingrsakeyexponent"),
    INVALID_VERSION("invalidversion"),
    MISSING_VERSION("missingversion"),
    INVALID_ID("invalidid"),
    MISSING_ID("missingid"),
    MISSING_SUBJECT_CONFIRMATION("missingsubjectconfirmation"),
    MISSING_SUBJECT_CONFIRMATION_METHOD("missingsubjectconfirmationmethod"),
    MISSING_SUBJECT("missingsubject"),
    MISSING_SUBJECT_NAMEID("missingsubjectnameid"),
    MISSING_ISSUER("missingissuer"),
    MISSING_ISSUER_FORMAT("missingissuerformat"),
    INVALID_ISSUER_EMAIL_FORMAT("invalidissueremailformat"),
    INVALID_ISSUER_X509_FORMAT("invalidissuerx509format"),
    INVALID_ISSUER_WINDOWS_DOMAIN_FORMAT("invalidissuerwindowsdomainformat"),
    MISSING_ISSUEINSTANT("missingissueinstant"),
    INVALID_ISSUEINSTANT("invalidissueinstant"),
    INVALID_RSA_PUBLIC_KEY_MODULUS("invalidrsapublickeymodulus"),
    INVALID_RSA_PUBLIC_KEY_EXPONENT("invalidrsapublickeyexponent"),
    INVALID_SUBJECT_NAMEID_FORMAT("invalidsubjectnameidformat"),
    INVALID_X509_CERTIFICATE("invalidx509certificate"),
    LATE_ISSUEINSTANT("lateissueinstant"),
    MISSING_SUBJECT_CONFIRMATION_DATA("missingsubjectconfdata"),
    MISSING_SUBJECT_CONFIRMATION_KEYINFO("missingsubjectconfirmationkeyinfo"),
    MISSING_SUBJECT_CONF_RSA_PUBLIC_KEY_EXPONENT("missingsubjectconfrsapublickeyexponent"),
    INVALID_SUBJECT_CONF_RSA_PUBLIC_KEY_MODULUS("invalidsubjectconfrsapublickeymodulus"),
    INVALID_SUBJECT_CONF_RSA_PUBLIC_KEY_EXPONENT("invalidsubjectconfrsapublickeyexponent"),
    UNKNOWN_AUDIENCE("unknownaudience"),
    INVALID_AUTHN_CONTEXT_CLASS_REF("invalidauthncontext"),
    SECOND_AUTHN_CONTEXT_CLASS_REF("secondauthncontext"),
    SECOND_ROLE("secondrole"),
    SECOND_PURPOSE_OF_USE("secondpurposeofuse"),
    WITH_AUTHZ_CONSENT("withauthzconsent"),
    ACP_VALID("acpvalid"),
    TRUSTPROPERTY_AND_INVALIDMODULUS("trustpropertyandinvalidmodulus"),
    TRUSTPROPERTY_AND_VALIDMODULUS("trustpropertyandvalidmodulus"),
    NOTRUSTPROPERTY_AND_INVALIDMODULUS("notrustpropertyandinvalidmodulus"),
    NOTRUSTPROPERTY_AND_VALIDMODULUS("notrustpropertyandvalidmodulus");

    /** Constant <code>KEY="connectathon"</code> */
    private static final String KEY = "connectathon";
    private String name;
    private ProfileRole[] roles;

    private AssertionProfile(String name) {
        this.name = name;
        this.roles = new ProfileRole[]{ProfileRole.USER};
    }

    private AssertionProfile(String name, ProfileRole[] roles) {
        this.name = name;
        this.roles = roles;
    }

    /**
     * Get AssertionProfile from the principal name.
     *
     * @param name a {@link java.lang.String} object.
     * @return AssertionProfile enum value if name exists, null otherwise
     */
    public static AssertionProfile getFromName(String name) {
        for (AssertionProfile profile : AssertionProfile.values()) {
            if (profile.getName().equals(name)) {
                return profile;
            }
        }
        return null;
    }

    /**
     * If name is extract from assertion subject, it can be modified by some test case scenarios or specific
     * TokenProvider. This method is able to retrieve the original assertion profile.
     *
     * @param subject a {@link java.lang.String} object.
     * @return a {@link net.ihe.gazelle.sts.constants.AssertionProfile} object.
     */
    public static AssertionProfile getFromSubject(String subject) {
        if (subject.contains("@")) {
            subject = subject.replaceFirst("@.*$", "");
        }
        return AssertionProfile.getFromName(subject);
    }

    /**
     * <p>Getter for the field <code>name</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getName() {
        return name;
    }

    /**
     * <p>getPassword.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getPassword() {
        return KEY;
    }

    /**
     * <p>Getter for the field <code>roles</code>.</p>
     *
     * @return an array of {@link net.ihe.gazelle.sts.constants.ProfileRole} objects.
     */
    public ProfileRole[] getRoles() {
        return roles.clone();
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return getName();
    }

}
