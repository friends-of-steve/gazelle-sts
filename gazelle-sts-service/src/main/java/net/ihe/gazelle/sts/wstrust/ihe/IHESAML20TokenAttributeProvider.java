package net.ihe.gazelle.sts.wstrust.ihe;

import net.ihe.gazelle.sts.config.AssertionProperties;
import net.ihe.gazelle.sts.config.IHEAssertionProperties;
import net.ihe.gazelle.sts.constants.AssertionProfile;
import net.ihe.gazelle.sts.saml.AbstractHL7v3CodedElement;
import net.ihe.gazelle.sts.saml.PurposeOfUse;
import net.ihe.gazelle.sts.saml.Role;
import net.ihe.gazelle.sts.wstrust.common.ExtendedSAML20TokenAttributeProvider;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;

import java.util.Map;

/**
 * <p>IHESAML20TokenAttributeProvider class.</p>
 *
 * @version $Id: $Id
 */
public class IHESAML20TokenAttributeProvider implements ExtendedSAML20TokenAttributeProvider {

    /*
      Constant <code>NAMEFORMAT_BASIC="urn:oasis:names:tc:SAML:2.0:attrname-fo"{trunked}</code>

    public static final String NAMEFORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
     */
    /**
     * Constant <code>NAMEFORMAT_URI="urn:oasis:names:tc:SAML:2.0:attrname-fo"{trunked}</code>
     */
    public static final String NAMEFORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    /**
     * Constant <code>SUBJECTID_FRIENDLYNAME="XSPA Subject"</code>
     */
    public static final String SUBJECTID_FRIENDLYNAME = "XSPA Subject";
    /**
     * Constant <code>SUBJECTID_NAME="urn:oasis:names:tc:xacml:1.0:subject:su"{trunked}</code>
     */
    public static final String SUBJECTID_NAME = "urn:oasis:names:tc:xspa:1.0:subject:subject-id";
    /**
     * Constant <code>ORGANIZATION_FRIENDLYNAME="XSPA Organization"</code>
     */
    public static final String ORGANIZATION_FRIENDLYNAME = "XSPA Organization";
    /**
     * Constant <code>ORGANIZATION_NAME="urn:oasis:names:tc:xspa:1.0:subject:org"{trunked}</code>
     */
    public static final String ORGANIZATION_NAME = "urn:oasis:names:tc:xspa:1.0:subject:organization";
    /**
     * Constant <code>ORGANIZATIONID_FRIENDLYNAME="XSPA Organization ID"</code>
     */
    public static final String ORGANIZATIONID_FRIENDLYNAME = "XSPA Organization ID";
    /**
     * Constant <code>ORGANIZATIONID_NAME="urn:oasis:names:tc:xspa:1.0:subject:org"{trunked}</code>
     */
    public static final String ORGANIZATIONID_NAME = "urn:oasis:names:tc:xspa:1.0:subject:organization-id";
    /**
     * Constant <code>HOMECOMMUNITYID_FRIENDLYNAME="XCA Home Community ID"</code>
     */
    public static final String HOMECOMMUNITYID_FRIENDLYNAME = "XCA Home Community ID";
    /**
     * Constant <code>HOMECOMMUNITYID_NAME="urn:ihe:iti:xca:2010:homeCommunityId"</code>
     */
    public static final String HOMECOMMUNITYID_NAME = "urn:ihe:iti:xca:2010:homeCommunityId";
    /**
     * Constant <code>AUTHZCONSENT_NAME="urn:ihe:iti:bppc:2007:docid"</code>
     */
    public static final String AUTHZCONSENT_NAME = "urn:ihe:iti:bppc:2007:docid";
    /**
     * Constant <code>AUTHZCONSENT_FRIENDLYNAME="Patient Privacy Policy Acknowledgement "{trunked}</code>
     */
    public static final String AUTHZCONSENT_FRIENDLYNAME = "Patient Privacy Policy Acknowledgement Document";
    /**
     * Constant <code>RESOURCEID_NAME="urn:oasis:names:tc:xacml:2.0:resource:r"{trunked}</code>
     */
    public static final String RESOURCEID_NAME = "urn:oasis:names:tc:xacml:2.0:resource:resource-id";
    /**
     * Constant <code>ROLE_NAME="urn:oasis:names:tc:xacml:2.0:subject:ro"{trunked}</code>
     */
    public static final String ROLE_NAME = "urn:oasis:names:tc:xacml:2.0:subject:role";
    /**
     * Constant <code>PURPOSEOFUSE_NAME="urn:oasis:names:tc:xspa:1.0:subject:pur"{trunked}</code>
     */
    public static final String PURPOSEOFUSE_NAME = "urn:oasis:names:tc:xspa:1.0:subject:purposeofuse";
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    private static final String DEFAULT_SUBJECTID_VALUE = "Default IHE Testing User";

    private String organizationAttributeValue;
    private String organizationIdAttributeValue;
    private String homeCommunityIdAttributeValue;
    private String homeCommunityIdAttributeName;
    private String homeCommunityIdAttributeAlternateName;
    private String authzConsentAttributeValue;
    private String resourceIDAttributeValue;

    // Add Steve Moore, 2023.04.01, to support code value lookup
    private final CodedValueFactory codedValueFactory = new CodedValueFactory();

    /**
     * {@inheritDoc}
     */
    public void setProperties(Map<String, String> properties) {

        AssertionProperties assertionProperties = provideAssertionProperties();

        organizationAttributeValue = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_ORGANIZATION_VALUE);
        organizationIdAttributeValue = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_ORGANIZATIONID_VALUE);
        homeCommunityIdAttributeValue = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_HOMECOMMUNITYID_VALUE);
        homeCommunityIdAttributeName = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_HOMECOMMUNITYID_NAME);
        homeCommunityIdAttributeAlternateName = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_HOMECOMMUNITYID_ALTERNATENAME);

        authzConsentAttributeValue = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_AUTHZCONSENT_VALUE);
        resourceIDAttributeValue = assertionProperties.getProperty(
                AssertionProperties.Keys.ATTRIBUTESTATEMENT_RESOURCEID_VALUE);
    }

    /**
     * <p>getAttributeStatement.</p>
     *
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType} object.
     */
    public AttributeStatementType getAttributeStatement() {

        AttributeStatementType attributeStatement = new AttributeStatementType();

        attributeStatement.addAttribute(new ASTChoiceType(getSubjectIdAttribute(DEFAULT_SUBJECTID_VALUE)));
        attributeStatement.addAttribute(new ASTChoiceType(getOrganizationAttribute(organizationAttributeValue)));
        attributeStatement.addAttribute(new ASTChoiceType(getOrganizationIdAttribute(organizationIdAttributeValue)));
        attributeStatement.addAttribute(new ASTChoiceType(getHomeCommunityIdAttribute(homeCommunityIdAttributeName, homeCommunityIdAttributeValue)));

        return attributeStatement;
    }

    /**
     * {@inheritDoc}
     */
    public AttributeStatementType getAttributeStatement(WSTrustRequestContext context) {

        if (context != null && context.getCallerPrincipal() != null && context.getCallerPrincipal()
                .getName() != null && !context.getCallerPrincipal().getName().isEmpty()) {

            AssertionProperties assertionProperties = provideAssertionProperties();
            AttributeStatementType attributeStatement = new AttributeStatementType();
            String principalName = context.getCallerPrincipal().getName();

            /* Updated by Matt MLB mblackmo 9/12/2020 Fixing the VALID issue for subject-id attribute value */
            attributeStatement.addAttribute(new ASTChoiceType(getSubjectIdAttribute(principalName)));

            attributeStatement.addAttribute(new ASTChoiceType(getOrganizationAttribute(organizationAttributeValue)));
            attributeStatement
                    .addAttribute(new ASTChoiceType(getOrganizationIdAttribute(organizationIdAttributeValue)));
            attributeStatement
                    .addAttribute(new ASTChoiceType(getHomeCommunityIdAttribute(homeCommunityIdAttributeName, homeCommunityIdAttributeValue)));

            if (homeCommunityIdAttributeAlternateName != null && ! homeCommunityIdAttributeAlternateName.isEmpty()) {
                attributeStatement
                        .addAttribute(new ASTChoiceType(getHomeCommunityIdAttribute(homeCommunityIdAttributeAlternateName, homeCommunityIdAttributeValue)));
            }

            AttributeType roleAttribute = buildRoleAttribute(principalName, assertionProperties);
            attributeStatement.addAttribute(new ASTChoiceType(roleAttribute));

            AttributeType purposeOfUseAttribute = buildPurposeOfUseAttribute(principalName, assertionProperties);
            attributeStatement.addAttribute(new ASTChoiceType(purposeOfUseAttribute));

            // Augment with additional attributes that are keyed from the principalName.
            // Not all values of principalName will trigger these additional attributes.
            attributeStatement = augmentAttributeStatement(attributeStatement, principalName);


            if (context.getCallerPrincipal().getName().equals(AssertionProfile.WITH_AUTHZ_CONSENT.getName())) {
                attributeStatement
                        .addAttribute(new ASTChoiceType(getAuthzConsentAttribute(authzConsentAttributeValue)));
                attributeStatement
                        .addAttribute(new ASTChoiceType(getSimpleAttribute(RESOURCEID_NAME, resourceIDAttributeValue)));
            }

            return attributeStatement;

        } else {
            logger.warn("Principal is not defined, Default attribute provider behaviour will be used");
            return getAttributeStatement();
        }

    }

    /**
     * <p>getSubjectIdAttribute.</p>
     *
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getSubjectIdAttribute(String attributeValue) {
        // Edited my Matt Blackmon MLB mblackmon 9/2020 to resolve the :basic :uri issue
        // return getAttribute(SUBJECTID_NAME, SUBJECTID_FRIENDLYNAME, NAMEFORMAT_BASIC, attributeValue);

        logger.warn("MLB DEBUG 2022: In getSubjectIdAttribute: " + attributeValue);
        if (attributeValue .equals("valid")) {
            logger.warn("MLB DEBUG 2022 valid branch: In getSubjectIdAttribute if branch: Found " + attributeValue );
            //return getAttribute(SUBJECTID_NAME, SUBJECTID_FRIENDLYNAME, NAMEFORMAT_BASIC, "urn:oid:2.16.840.1.113883.3.7418.2.1");
            // This return WORKS fine returning the value
            // 3-31-2023 MLB changed return getAttribute(SUBJECTID_NAME, SUBJECTID_FRIENDLYNAME, NAMEFORMAT_URI,"urn:oid:2.16.840.1.113883.3.7418.2.1");
            return getAttribute(SUBJECTID_NAME, SUBJECTID_FRIENDLYNAME, NAMEFORMAT_URI,"urn:oid:2.16.840.1.113883.3.7418.2.1");
        }
        else {
            logger.warn("MLB DEBUG 2022 valid branch: In getSubjectIdAttribute else branch: Found " + attributeValue );
            return getAttribute(SUBJECTID_NAME, SUBJECTID_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
        }
    }

    /**
     * <p>augmentAttributeStatement.</p>
     * Semi hard-coded method that adds to the AttributeStatement list.
     * The method constructs a key from the basenames of two properties plus the principalName.
     * If we find values for those keys, we add them to the attribute list.
     * @param statement a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;} object.
     * @param principalName a {@link java.lang.String;} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */

    private AttributeStatementType augmentAttributeStatement(AttributeStatementType statement, String principalName) {

        AssertionProperties assertionProperties = provideAssertionProperties();

        // This code could be reduced. I chose readability over efficiency.

        String keyCSP = AssertionProperties.Keys.ATTRIBUTESTATEMENT_CSP_BASE.getKeyValue() + "." + principalName;
        String valueCSP = assertionProperties.getProperty(keyCSP);
        statement = addAttribute(statement, valueCSP);

        String keyValidatedAttributes = AssertionProperties.Keys.ATTRIBUTESTATEMENT_VALIDATEDATTRIBUTES_BASE.getKeyValue() + "." + principalName;
        String valueValidatedAttributes = assertionProperties.getProperty(keyValidatedAttributes);
        statement = addAttribute(statement, valueValidatedAttributes);

        return statement;
    }

    /**
     * <p>addAttribute.</p>
     * Method accepts a tab-delimited string that represents four tokens that will comprise a new attribute.
     * If the caller passes a null string or empty string, the method does not alter the Attribute Statement.
     * If the token string yields 4 tokens, a new attribute is created and added to the list of attributes.
     * The tokens, in order, are:
     *  name
     *  friendlyName
     *  nameFormat
     *  value
     * @param statement a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;} object.
     * @param tokenString a {@link java.lang.String;} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    private AttributeStatementType addAttribute(AttributeStatementType statement, String tokenString) {
        if (tokenString != null && !tokenString.isEmpty()) {
            String[] tokens = tokenString.split("\t");
            if (tokens.length == 4) {
                String name           = tokens[0];
                String friendlyName   = tokens[1];
                String nameFormat     = tokens[2];
                String attributeValue = tokens[3];
                statement.addAttribute(new ASTChoiceType(getAttribute(name, friendlyName, nameFormat, attributeValue)));
            }
        }
        return statement;
    }

    /**
     * <p>getOrganizationAttribute.</p>
     *
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getOrganizationAttribute(String attributeValue) {
        return getAttribute(ORGANIZATION_NAME, ORGANIZATION_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
    }

    /**
     * <p>getOrganizationIdAttribute.</p>
     *
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getOrganizationIdAttribute(String attributeValue) {
        return getAttribute(ORGANIZATIONID_NAME, ORGANIZATIONID_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
    }

    /**
     * <p>getHomeCommunityIdAttribute.</p>
     *
     * @param attributeName a {@link java.lang.String} object.
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getHomeCommunityIdAttribute(String attributeName, String attributeValue) {
        if (attributeName == null || attributeName.isEmpty()) {
            return getAttribute(HOMECOMMUNITYID_NAME, HOMECOMMUNITYID_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
        } else {
            return getAttribute(attributeName, HOMECOMMUNITYID_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
        }
    }

    /**
     * <p>getAuthzConsentAttribute.</p>
     *
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getAuthzConsentAttribute(String attributeValue) {
        return getAttribute(AUTHZCONSENT_NAME, AUTHZCONSENT_FRIENDLYNAME, NAMEFORMAT_URI, attributeValue);
    }

    /**
     * <p>buildRoleAttribute.</p>
     *
     * @param principalName       a {@link java.lang.String} object.
     * @param assertionProperties a {@link net.ihe.gazelle.sts.config.AssertionProperties} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType buildRoleAttribute(String principalName, AssertionProperties assertionProperties) {

        String roleAttributeValueCode;
        String roleAttributeValueCodeSystem;
        String roleAttributeValueCodeSystemName;
        String roleAttributeValueDisplayName;

        if (principalName.equals(AssertionProfile.SECOND_ROLE.getName())) {
            roleAttributeValueCode = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODE);
            roleAttributeValueCodeSystem = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODESYSTEM);
            roleAttributeValueCodeSystemName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL2_CODESYSTEMNAME);
            roleAttributeValueDisplayName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL2_DISPLAYNAME);
        } else {
            roleAttributeValueCode = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODE);
            roleAttributeValueCodeSystem = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODESYSTEM);
            roleAttributeValueCodeSystemName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL1_CODESYSTEMNAME
            );
            roleAttributeValueDisplayName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL1_DISPLAYNAME);
        }

        return getRoleAttribute(roleAttributeValueCode, roleAttributeValueCodeSystem, roleAttributeValueCodeSystemName,
                roleAttributeValueDisplayName);
    }

    /**
     * <p>buildPurposeOfUseAttribute.</p>
     *
     * @param principalName       a {@link java.lang.String} object.
     * @param assertionProperties a {@link net.ihe.gazelle.sts.config.AssertionProperties} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType buildPurposeOfUseAttribute(String principalName, AssertionProperties assertionProperties) {

        String purposeofuseAttributeValueCode;
        String purposeofuseAttributeValueCodeSystem;
        String purposeofuseAttributeValueCodeSystemName;
        String purposeofuseAttributeValueDisplayName;

        if (principalName.equals(AssertionProfile.SECOND_PURPOSE_OF_USE.getName())) {
            purposeofuseAttributeValueCode = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODE);
            purposeofuseAttributeValueCodeSystem = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODESYSTEM);
            purposeofuseAttributeValueCodeSystemName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_CODESYSTEMNAME);
            purposeofuseAttributeValueDisplayName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_DISPLAYNAME);
        } else if (principalName.startsWith(AssertionProfile.SECOND_PURPOSE_OF_USE.getName())) {
            String[] tokens = principalName.split("\\.");
            String identifier = tokens[1];
            CodedValue codedValue = codedValueFactory.getCodedValue(identifier);
            purposeofuseAttributeValueCode           = codedValue.getCode();
            purposeofuseAttributeValueCodeSystem     = codedValue.getCodingSystemUID();
            purposeofuseAttributeValueCodeSystemName = codedValue.getCodingSystemName();
            purposeofuseAttributeValueDisplayName    = codedValue.getDisplayName();
        } else {
            purposeofuseAttributeValueCode = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODE);
            purposeofuseAttributeValueCodeSystem = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODESYSTEM);
            purposeofuseAttributeValueCodeSystemName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_CODESYSTEMNAME);
            purposeofuseAttributeValueDisplayName = assertionProperties.getProperty(
                    AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_DISPLAYNAME);
        }

        return getPurposeOfUseAttribute(purposeofuseAttributeValueCode, purposeofuseAttributeValueCodeSystem,
                purposeofuseAttributeValueCodeSystemName, purposeofuseAttributeValueDisplayName);
    }

    /**
     * <p>getRoleAttribute.</p>
     *
     * @param code           a {@link java.lang.String} object.
     * @param codeSystem     a {@link java.lang.String} object.
     * @param codeSystemName a {@link java.lang.String} object.
     * @param displayName    a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getRoleAttribute(String code, String codeSystem, String codeSystemName,
                                             String displayName) {
        return getHL7v3CodedElementAttribute(ROLE_NAME, new Role(), code, codeSystem, codeSystemName, displayName);
    }

    /**
     * <p>getPurposeOfUseAttribute.</p>
     *
     * @param code           a {@link java.lang.String} object.
     * @param codeSystem     a {@link java.lang.String} object.
     * @param codeSystemName a {@link java.lang.String} object.
     * @param displayName    a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getPurposeOfUseAttribute(String code, String codeSystem, String codeSystemName,
                                                     String displayName) {
        return getHL7v3CodedElementAttribute(PURPOSEOFUSE_NAME, new PurposeOfUse(), code, codeSystem, codeSystemName,
                displayName);
    }

    /**
     * <p>getHL7v3CodedElementAttribute.</p>
     *
     * @param attributeName  a {@link java.lang.String} object.
     * @param codedElement   a {@link net.ihe.gazelle.sts.saml.AbstractHL7v3CodedElement} object.
     * @param code           a {@link java.lang.String} object.
     * @param codeSystem     a {@link java.lang.String} object.
     * @param codeSystemName a {@link java.lang.String} object.
     * @param displayName    a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getHL7v3CodedElementAttribute(String attributeName, AbstractHL7v3CodedElement codedElement,
                                                          String code, String codeSystem, String codeSystemName,
                                                          String displayName) {
        AttributeType codedElementAttribute = new AttributeType(attributeName);
        codedElement.setCode(code);
        codedElement.setCodeSystem(codeSystem);
        codedElement.setCodeSystemName(codeSystemName);
        codedElement.setDisplayName(displayName);
        codedElementAttribute.addAttributeValue(codedElement);
        return codedElementAttribute;
    }

    protected AttributeType getCSPAttribute(String attributeValue) {
        return getAttribute("csp", "CSP", "foo", attributeValue);
    }

    protected AttributeType getValidatedAttributesAttribute(String attributeValue) {
        return getAttribute("validated_attributes", "Validated Attributes", "", attributeValue);
    }

    /**
     * <p>getAttribute.</p>
     *
     * @param name           a {@link java.lang.String} object.
     * @param friendlyName   a {@link java.lang.String} object.
     * @param nameFormat     a {@link java.lang.String} object.
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getAttribute(String name, String friendlyName, String nameFormat, String attributeValue) {
        AttributeType attributeType = new AttributeType(name);
        attributeType.setFriendlyName(friendlyName);
        attributeType.setNameFormat(nameFormat);
        attributeType.addAttributeValue(attributeValue);
        return attributeType;
    }

    /**
     * <p>getSimpleAttribute.</p>
     *
     * @param name           a {@link java.lang.String} object.
     * @param attributeValue a {@link java.lang.String} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AttributeType} object.
     */
    protected AttributeType getSimpleAttribute(String name, String attributeValue) {
        AttributeType simpleAttribute = new AttributeType(name);
        simpleAttribute.addAttributeValue(attributeValue);
        return simpleAttribute;
    }

    /**
     * <p>provideAssertionProperties.</p>
     *
     * @return a {@link net.ihe.gazelle.sts.config.AssertionProperties} object.
     */
    protected AssertionProperties provideAssertionProperties() {
        return new IHEAssertionProperties();
    }


}
