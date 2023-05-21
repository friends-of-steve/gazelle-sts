package net.ihe.gazelle.sts.config;

import net.ihe.gazelle.sts.wstrust.GazelleSTSService;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * <p>Abstract AssertionProperties class.</p>
 *
 * @author cel
 * @version $Id: $Id
 */
public abstract class AssertionProperties {

    private final String rootPath;
    protected Properties properties;

    AssertionProperties(String rootPath) {
        if (rootPath != null && !rootPath.isEmpty()) {
            this.rootPath = rootPath;
        } else {
            throw new IllegalArgumentException("RootPath must be defined to instantiate assertion properties");
        }
    }

    public AssertionProperties() {
        this.rootPath = GazelleSTSService.STS_CONFIG_DIR;
    }

    String getRootPath() {
        return rootPath;
    }

    /**
     * <p>getProperty.</p>
     *
     * @param key a {@link net.ihe.gazelle.sts.config.AssertionProperties.Keys} object.
     * @return a {@link java.lang.String} object.
     */
    public String getProperty(Keys key) {
        String propertyValue = getProperties().getProperty(key.getKeyValue());
        if (propertyValue != null){
            return propertyValue;
        } else {
            throw new MissingPropertyException(String.format("Missing property with key '%s'", key.getKeyValue()));
        }
    }

    public String getProperty(String key) {
        String propertyValue = getProperties().getProperty(key);

        // propertyValue is allowed to be null. Let the caller manage that
        return propertyValue;
    }

    /**
     * <p>getPropertyFilePath.</p>
     *
     * @param root a {@link java.lang.String} object.
     * @return a {@link java.lang.String} object.
     */
    protected abstract String getPropertyFilePath(String root);

    /**
     * <p>Getter for the field <code>properties</code>.</p>
     *
     * @return a {@link java.util.Properties} object.
     */
    protected Properties getProperties() {
        if (properties == null) {
            properties = new Properties();
            String propertyFilePath = getPropertyFilePath(getRootPath());
            try {
                FileInputStream fileInputStream = new FileInputStream(propertyFilePath);
                properties.load(fileInputStream);
            } catch (FileNotFoundException e) {
                throw new MissingPropertyFileException(String.format("Property file not found at '%s'", propertyFilePath));
            } catch (IOException e) {
                throw new CannotReadPropertyFileException(String.format("Cannot read property file at '%s' with message : %s", propertyFilePath,
                        e.getMessage()), e);
            }
        }
        return properties;
    }

    public enum Keys {

        DOMAIN("Domain"),
        ISSUER("Issuer"),
        SUBJECT_CONFIRMATION_METHOD("Subject.Confirmation.Method"),
        AUTHNSTATEMENT_CONTEXT_CLASSREF("AuthnStatement.Context.ClassRef"),

        ATTRIBUTESTATEMENT_ORGANIZATION_VALUE("AttributeStatement.Organization.Value"),
        ATTRIBUTESTATEMENT_ORGANIZATIONID_VALUE("AttributeStatement.OrganizationId.Value"),
        ATTRIBUTESTATEMENT_HOMECOMMUNITYID_VALUE("AttributeStatement.HomeCommunityId.Value"),

        ATTRIBUTESTATEMENT_AUTHZCONSENT_VALUE("AttributeStatement.Authzconsent.Value"),
        ATTRIBUTESTATEMENT_RESOURCEID_VALUE("AttributeStatement.ResourceId.Value"),

        ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODE("AttributeStatement.Role.Level1.code"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODESYSTEM("AttributeStatement.Role.Level1.codeSystem"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODESYSTEMNAME("AttributeStatement.Role.Level1.codeSystemName"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL1_DISPLAYNAME("AttributeStatement.Role.Level1.displayName"),

        ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODE("AttributeStatement.Role.Level2.code"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODESYSTEM("AttributeStatement.Role.Level2.codeSystem"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODESYSTEMNAME("AttributeStatement.Role.Level2.codeSystemName"),
        ATTRIBUTESTATEMENT_ROLE_LEVEL2_DISPLAYNAME("AttributeStatement.Role.Level2.displayName"),

        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODE("AttributeStatement.PurposeOfUse.Level1.code"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODESYSTEM("AttributeStatement.PurposeOfUse.Level1.codeSystem"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODESYSTEMNAME("AttributeStatement.PurposeOfUse.Level1.codeSystemName"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_DISPLAYNAME("AttributeStatement.PurposeOfUse.Level1.displayName"),

        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODE("AttributeStatement.PurposeOfUse.Level2.code"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODESYSTEM("AttributeStatement.PurposeOfUse.Level2.codeSystem"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODESYSTEMNAME("AttributeStatement.PurposeOfUse.Level2.codeSystemName"),
        ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_DISPLAYNAME("AttributeStatement.PurposeOfUse.Level2.displayName"),

        ATTRIBUTESTATEMENT_CSP_BASE("AttributeStatement.CSP"),
        ATTRIBUTESTATEMENT_VALIDATEDATTRIBUTES_BASE("AttributeStatement.ValidatedAttributes");



        private String keyValue;

        Keys(String keyValue) {
            this.keyValue = keyValue;
        }

        public String getKeyValue() {
            return keyValue;
        }
    }

}
