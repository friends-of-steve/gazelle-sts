/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ihe.gazelle.sts.wstrust.ihe;

import net.ihe.gazelle.sts.config.*;
import net.ihe.gazelle.sts.constants.AssertionProfile;
import net.ihe.gazelle.sts.saml.IHESAMLUtil;
import net.ihe.gazelle.sts.wstrust.common.ExtendedSAML20TokenAttributeProvider;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.StatementUtil;
import org.picketlink.identity.federation.core.sts.AbstractSecurityTokenProvider;
import org.picketlink.identity.federation.core.wstrust.SecurityToken;
import org.picketlink.identity.federation.core.wstrust.StandardSecurityToken;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.RequestedReferenceType;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.wss.secext.KeyIdentifierType;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * A {@code SecurityTokenProvider} implementation that handles WS-Trust SAML 2.0 token requests.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @version $Id: $Id
 */
public class IHESAML20TokenProvider extends AbstractSecurityTokenProvider implements SecurityTokenProvider {

    /**
     * Constant <code>SAML2_NS="urn:oasis:names:tc:SAML:2.0:assertion"</code>
     */
    public static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    /**
     * Constant <code>XMLDSIG_NS="http://www.w3.org/2000/09/xmldsig#"</code>
     */
    public static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    /**
     * Constant <code>EMAIL_REGEX</code>
     */
    protected static final String EMAIL_REGEX = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
    /**
     * Constant <code>DISTINGUISH_NAME_REGEX</code>
     */
    protected static final String DISTINGUISH_NAME_REGEX = "(([a-zA-Z]+)=([^,]*)(, ?||$))+";
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    private static final long HOUR24_MILLI = 86400000;
    protected ExtendedSAML20TokenAttributeProvider attributeProvider;

    protected boolean useAbsoluteKeyIdentifier = false;
    protected AssertionProperties assertionProperties;
    protected String domain = null;

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#initialize(java.util.Map)
     */

    /**
     * {@inheritDoc}
     */
    public void initialize(Map<String, String> properties) {
        super.initialize(properties);

        // Check if an attribute provider has been set.
        String attributeProviderClassName = this.properties.get(ATTRIBUTE_PROVIDER);
        if (attributeProviderClassName == null) {
            logger.trace("No attribute provider set");
        } else {
            try {
                Class<?> clazz = SecurityActions
                        .loadClass(getClass(), attributeProviderClassName);
                Object object = clazz.newInstance();
                if (object instanceof ExtendedSAML20TokenAttributeProvider) {
                    this.attributeProvider = (ExtendedSAML20TokenAttributeProvider) object;
                    this.attributeProvider.setProperties(this.properties);
                } else {
                    logger.stsWrongAttributeProviderTypeNotInstalled(attributeProviderClassName);
                }
            } catch (Exception pae) {
                logger.attributeProviderInstationError(pae);
            }
        }

        String absoluteKI = this.properties.get(USE_ABSOLUTE_KEYIDENTIFIER);
        if (absoluteKI != null && "true".equalsIgnoreCase(absoluteKI)) {
            useAbsoluteKeyIdentifier = true;
        }

        assertionProperties = provideAssertionProperties();
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
     * cancelToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
     */

    /**
     * {@inheritDoc}
     */
    public void cancelToken(ProtocolContext protoContext) throws ProcessingException {
        if (!(protoContext instanceof WSTrustRequestContext)) {
            return;
        }

        WSTrustRequestContext context = (WSTrustRequestContext) protoContext;

        // get the assertion that must be canceled.
        Element token = context.getRequestSecurityToken().getCancelTargetElement();
        if (token == null) {
            throw logger.wsTrustNullCancelTargetError();
        }
        Element assertionElement = (Element) token.getFirstChild();
        if (!this.isAssertion(assertionElement)) {
            throw logger.assertionInvalidError();
        }

        // get the assertion ID and add it to the canceled assertions set.
        String assertionId = assertionElement.getAttribute("ID");
        this.revocationRegistry.revokeToken(SAMLUtil.SAML2_TOKEN_TYPE, assertionId);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
     * issueToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
     */

    /**
     * {@inheritDoc}
     */
    public void issueToken(ProtocolContext protoContext) throws ProcessingException {

        String authnStatementContextClassRef = "";
        authnStatementContextClassRef = assertionProperties
                .getProperty(AssertionProperties.Keys.AUTHNSTATEMENT_CONTEXT_CLASSREF);

        if (!(protoContext instanceof WSTrustRequestContext)) {
            return;
        }

        WSTrustRequestContext context = (WSTrustRequestContext) protoContext;

        // the assertion principal (default is caller principal)
        Principal principal = context.getCallerPrincipal();

        // generate an id for the new assertion.
        String assertionID = IDGenerator.create("ID_");

        // lifetime and audience restrictions.
        Lifetime lifetime = adjustLifetimeForClockSkew(context.getRequestSecurityToken().getLifetime());
        AudienceRestrictionType restriction = null;
        AppliesTo appliesTo = context.getRequestSecurityToken().getAppliesTo();
        if (appliesTo != null) {
            if (principal.getName().equals(AssertionProfile.UNKNOWN_AUDIENCE.getName())) {
                restriction = SAMLAssertionFactory
                        .createAudienceRestriction("http://ihe.unknown.xua/X-ServiceProvider-IHE-Unknown");
            } else {
                restriction = SAMLAssertionFactory.createAudienceRestriction(WSTrustUtil.parseAppliesTo(appliesTo));
            }
        }

        ConditionsType conditions = SAMLAssertionFactory.createConditions(lifetime.getCreated(), lifetime.getExpires(),
                restriction);

        /*
         * ------------------------------
         * Created by IHE-Europe (fgate)
         * ------------------------------
         * - SUBJECT ELEMENT -
         * Get the SubjectConfirmation method value from the file parameters.assertion
         */

        SubjectType subject = getSubjectType(context, principal);

        List<StatementAbstractType> statements = new ArrayList<StatementAbstractType>();

        // create the attribute statements if necessary.
        Map<String, Object> claimedAttributes = context.getClaimedAttributes();
        if (claimedAttributes != null) {
            statements.add(StatementUtil.createAttributeStatement(claimedAttributes));
        }

        // create an AuthnStatement
        if (principal.getName().equals(AssertionProfile.SECOND_AUTHN_CONTEXT_CLASS_REF.getName())) {
            statements
                    .add(StatementUtil.createAuthnStatement(lifetime.getCreated(), JBossSAMLURIConstants.AC_IP.get()));
        } else if (principal.getName().equals(AssertionProfile.INVALID_AUTHN_CONTEXT_CLASS_REF.getName())) {
            statements.add(StatementUtil
                    .createAuthnStatement(lifetime.getCreated(), "urn:oasis:names:tc:SAML:2.0:ac:classes:Invalid"));
        } else {
            statements.add(StatementUtil.createAuthnStatement(lifetime.getCreated(), authnStatementContextClassRef));
        }

        // create the SAML assertion.
        NameIDType issuerID = getIssuerNameIDType(context, principal);

        AssertionType assertion = SAMLAssertionFactory.createAssertion(assertionID, issuerID, lifetime.getCreated(),
                conditions, subject, statements);

        if (this.attributeProvider != null) {
            AttributeStatementType attributeStatement = this.attributeProvider.getAttributeStatement(context);
            if (attributeStatement != null) {
                assertion.addStatement(attributeStatement);
            }
        }

        // convert the constructed assertion to element.
        Element assertionElement = null;
        try {
            assertionElement = IHESAMLUtil.toElement(assertion);
        } catch (Exception e) {
            throw logger.samlAssertionMarshallError(e);
        }

        assertionElement = postDomModification(assertionElement, principal);

        SecurityToken token = new StandardSecurityToken(context.getRequestSecurityToken().getTokenType().toString(),
                assertionElement, assertionID);
        context.setSecurityToken(token);

        // set the SAML assertion attached reference.
        String keyIdentifierValue = assertionID;
        if (!useAbsoluteKeyIdentifier) {
            keyIdentifierValue = "#" + keyIdentifierValue;
        }
        KeyIdentifierType keyIdentifier = WSTrustUtil
                .createKeyIdentifier(SAMLUtil.SAML2_VALUE_TYPE, keyIdentifierValue);
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(new QName(WSTrustConstants.WSSE11_NS, "TokenType", WSTrustConstants.WSSE.PREFIX_11),
                SAMLUtil.SAML2_TOKEN_TYPE);
        RequestedReferenceType attachedReference = WSTrustUtil.createRequestedReference(keyIdentifier, attributes);
        context.setAttachedReference(attachedReference);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
     * renewToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
     */

    /**
     * {@inheritDoc}
     */
    public void renewToken(ProtocolContext protoContext) throws ProcessingException {
        if (!(protoContext instanceof WSTrustRequestContext)) {
            return;
        }

        WSTrustRequestContext context = (WSTrustRequestContext) protoContext;
        // get the specified assertion that must be renewed.
        Element token = context.getRequestSecurityToken().getRenewTargetElement();
        if (token == null) {
            throw logger.wsTrustNullRenewTargetError();
        }
        Element oldAssertionElement = (Element) token.getFirstChild();
        if (!this.isAssertion(oldAssertionElement)) {
            throw logger.assertionInvalidError();
        }

        // get the JAXB representation of the old assertion.
        AssertionType oldAssertion = null;
        try {
            oldAssertion = IHESAMLUtil.fromElement(oldAssertionElement);
        } catch (Exception je) {
            throw logger.samlAssertionUnmarshallError(je);
        }

        // canceled assertions cannot be renewed.
        if (this.revocationRegistry.isRevoked(SAMLUtil.SAML2_TOKEN_TYPE, oldAssertion.getID())) {
            throw logger.samlAssertionRevokedCouldNotRenew(oldAssertion.getID());
        }

        // adjust the lifetime for the renewed assertion.
        ConditionsType conditions = oldAssertion.getConditions();
        Lifetime lifetime = adjustLifetimeForClockSkew(context.getRequestSecurityToken().getLifetime());
        conditions.setNotBefore(lifetime.getCreated());
        conditions.setNotOnOrAfter(lifetime.getExpires());

        // create a new unique ID for the renewed assertion.
        String assertionID = IDGenerator.create("ID_");

        List<StatementAbstractType> statements = new ArrayList<StatementAbstractType>();
        statements.addAll(oldAssertion.getStatements());

        // create the new assertion.
        AssertionType newAssertion = SAMLAssertionFactory.createAssertion(assertionID, oldAssertion.getIssuer(), context
                        .getRequestSecurityToken().getLifetime().getCreated(), conditions, oldAssertion.getSubject(),
                statements);

        // create a security token with the new assertion.
        Element assertionElement = null;
        try {
            assertionElement = IHESAMLUtil.toElement(newAssertion);
        } catch (Exception e) {
            throw logger.samlAssertionMarshallError(e);
        }

        SecurityToken securityToken = new StandardSecurityToken(
                context.getRequestSecurityToken().getTokenType().toString(),
                assertionElement, assertionID);
        context.setSecurityToken(securityToken);

        // set the SAML assertion attached reference.
        KeyIdentifierType keyIdentifier = WSTrustUtil.createKeyIdentifier(SAMLUtil.SAML2_VALUE_TYPE, "#" + assertionID);
        Map<QName, String> attributes = new HashMap<QName, String>();
        attributes.put(new QName(WSTrustConstants.WSSE11_NS, "TokenType"), SAMLUtil.SAML2_TOKEN_TYPE);
        RequestedReferenceType attachedReference = WSTrustUtil.createRequestedReference(keyIdentifier, attributes);
        context.setAttachedReference(attachedReference);
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
     * validateToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
     */

    /**
     * {@inheritDoc}
     */
    public void validateToken(ProtocolContext protoContext) throws ProcessingException {
        if (!(protoContext instanceof WSTrustRequestContext)) {
            return;
        }

        WSTrustRequestContext context = (WSTrustRequestContext) protoContext;

        logger.trace("SAML token validation started");

        // get the SAML assertion that must be validated.
        Element token = context.getRequestSecurityToken().getValidateTargetElement();
        if (token == null) {
            throw logger.wsTrustNullValidationTargetError();
        }

        String code = WSTrustConstants.STATUS_CODE_VALID;
        String reason = "SAMLV2.0 Assertion successfuly validated (with NO Authz-Consent option)";

        //pasre assertion
        AssertionType assertion = null;
        Element assertionElement = (Element) token.getFirstChild();
        if (!this.isAssertion(assertionElement)) {
            code = WSTrustConstants.STATUS_CODE_INVALID;
            reason = "Validation failure: supplied token is not a SAMLV2.0 Assertion";
        } else {
            try {
                if (logger.isTraceEnabled()) {
                    logger.samlAssertion(DocumentUtil.getNodeAsString(assertionElement));
                }
                assertion = IHESAMLUtil.fromElement(assertionElement);
            } catch (Exception e) {
                throw logger.samlAssertionUnmarshallError(e);
            }
        }

        boolean isResourceId = isResourceId(assertionElement);
        boolean isDocId = isDocId(assertionElement);

        if (assertion != null) {
            // check if the assertion has been canceled before.
            if (this.revocationRegistry.isRevoked(SAMLUtil.SAML2_TOKEN_TYPE, assertion.getID())) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: assertion with id " + assertion.getID() + " has been canceled";
            }

            /*
             * ------------------------------
             * Created by IHE-Europe (fgate)
             * ------------------------------
             * - ASSERTION VALIDATION WITH XUA TESTS CHARACTERISTICS -
             * I. The Audience element shall contain the value : "http://ihe.connectathon.xua/X-ServiceProvider-IHE-Connectathon"
             * II. The Conditions element shall contain a valid lifetime period
             * III. The AutnContextClassRef shall contain a valid value
             * IV. The AutnContextClassRef shall not be InternetProtocol
             * V. The attribute Role shall be Medical Doctor or Medical Assistant / Social Worker or Administrative Healthcare Staff
             * VI. The attribute PurposeOfUse shall be TREATMENT or EMERGENCY / PUBLICHEALTH or RESEARCH
             * VII. The assertion may contain an Authz-Consent option
             */

            // I. The Audience element shall contain an URI identifying the X-Service Provider. It may contain other Audience URI identifying the Affinity domain.
            boolean validAudience = false;
            if (assertion.getConditions() != null) {
                for (ConditionAbstractType typeCondition : assertion.getConditions().getConditions()) {
                    AudienceRestrictionType art = (AudienceRestrictionType) typeCondition;
                    List<URI> audiences = art.getAudience();
                    if (audiences.size() >= 1) {
                        validAudience = true;
                    }
                }
                if (!validAudience) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: Missing URI of X-Service_Provider in audience restriction";
                }
            } else {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Assertion should have conditions elements";
            }

            // II. The Conditions element shall contain a valid lifetime period
            try {
                long clockSkewInMilis = getClockSkewInMillis();
                if (AssertionUtil.hasExpired(assertion, clockSkewInMilis)) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: assertion expired or used before its lifetime period";
                }
            } catch (Exception ce) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: unable to verify assertion lifetime: " + ce.getMessage();
            }

            // III. The AutnContextClassRef shall contain a valid value
            try {
                Object[] tab_statements = assertion.getStatements().toArray();
                String value = (((AuthnStatementType) tab_statements[0]).getAuthnContext().getSequence().getClassRef()
                        .getValue()).toString();
                if (value.equals("urn:oasis:names:tc:SAML:2.0:ac:classes:Invalid")) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: invalid AuthnStatement parameter";
                }

                // IV. The AutnContextClassRef shall not be InternetProtocol
                if (value.equals("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol")) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: AuthnContextClassRef is 'InternetProtocol' which 'policy' says is an unacceptable authentication method";
                }
            } catch (Exception ce) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: unable to verify AuthContextClassRef value: " + ce.getMessage();
            }

            // V. The attribute Role shall be in the range of defined purposeOfUse
            String currentRole = getRole(assertionElement);
            String[] allowedRoles;

            allowedRoles = new String[2];
            allowedRoles[0] = assertionProperties
                    .getProperty(AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL1_DISPLAYNAME);
            allowedRoles[1] = assertionProperties
                    .getProperty(AssertionProperties.Keys.ATTRIBUTESTATEMENT_ROLE_LEVEL2_DISPLAYNAME);
            if (!currentRole.equals(allowedRoles[0])) {
                if (!currentRole.equals(allowedRoles[1])) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: unused or unknown role for the connectathon";
                } else {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: current role cannot provide any access";
                }
            }

            // VI. The attribute PurposeOfUse shall be in the range of defined purposeOfUse
            String currentPurposeOfUse = getPurposeOfUse(assertionElement);
            String[] allowedPurpuseOfUse;

            allowedPurpuseOfUse = new String[2];
            allowedPurpuseOfUse[0] = assertionProperties
                    .getProperty(AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL1_DISPLAYNAME);
            allowedPurpuseOfUse[1] = assertionProperties
                    .getProperty(AssertionProperties.Keys.ATTRIBUTESTATEMENT_PURPOSEOFUSE_LEVEL2_DISPLAYNAME);
            if (!currentPurposeOfUse.equals(allowedPurpuseOfUse[0])) {
                if (!currentPurposeOfUse.equals(allowedPurpuseOfUse[1])) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: unused or unknown purposeofuse for the connectathon";
                } else {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: current purposeofuse cannot provide any access";
                }
            }

            // VII. The assertion may contain an Authz-Consent option
            try {
                if (isDocId && isResourceId) {
                    reason = "SAMLV2.0 Assertion successfuly validated (WITH Authz-Consent option)";
                }
            } catch (Exception ce) {

            }
        }

        // construct the status and set it on the request context.
        StatusType status = new StatusType();
        status.setCode(code);
        status.setReason(reason);
        context.setStatus(status);
    }

    /**
     * <p>
     * Checks whether the specified element is a SAMLV2.0 assertion or not.
     * </p>
     *
     * @param element the {@code Element} being verified.
     * @return {@code true} if the element is a SAMLV2.0 assertion; {@code false} otherwise.
     */
    protected boolean isAssertion(Element element) {
        return element == null ? false : "Assertion".equals(element.getLocalName())
                && WSTrustConstants.SAML2_ASSERTION_NS.equals(element.getNamespaceURI());
    }

    /**
     * {@inheritDoc}
     */
    public boolean supports(String namespace) {
        return WSTrustConstants.BASE_NAMESPACE.equals(namespace);
    }

    /**
     * <p>tokenType.</p>
     *
     * @return a {@link java.lang.String} object.
     * @see SecurityTokenProvider#tokenType()
     */
    public String tokenType() {
        return SAMLUtil.SAML2_TOKEN_TYPE;
    }

    /**
     * <p>getSupportedQName.</p>
     *
     * @return a {@link javax.xml.namespace.QName} object.
     * @see SecurityTokenProvider#getSupportedQName()
     */
    public QName getSupportedQName() {
        return new QName(tokenType(), JBossSAMLConstants.ASSERTION.get());
    }

    /**
     * <p>family.</p>
     *
     * @return a {@link java.lang.String} object.
     * @see SecurityTokenProvider#family()
     */
    public String family() {
        return FAMILY_TYPE.WS_TRUST.toString();
    }

    /**
     * <p>getIssuerNameIDType.</p>
     *
     * @param context   a {@link org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext} object.
     * @param principal a {@link java.security.Principal} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.NameIDType} object.
     */
    protected NameIDType getIssuerNameIDType(WSTrustRequestContext context, Principal principal) {
        String issuer = context.getTokenIssuer();
        String format = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();

        // Identify format from issuer value
        if (issuer.matches(EMAIL_REGEX)) {
            format = JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get();
        }
        if (issuer.matches(DISTINGUISH_NAME_REGEX)) {
            format = JBossSAMLURIConstants.NAMEID_FORMAT_X509SUBJECTNAME.get();
        }

        // Handle error cases
        if (principal.getName().equals(AssertionProfile.INVALID_ISSUER_EMAIL_FORMAT.getName())) {
            format = JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get();
            issuer = issuer.replaceAll("@", "");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_ISSUER_X509_FORMAT.getName())) {
            format = JBossSAMLURIConstants.NAMEID_FORMAT_X509SUBJECTNAME.get();
            issuer = principal.getName().toLowerCase() + "@" + getDomain();
        }
        if (principal.getName().equals(AssertionProfile.INVALID_ISSUER_WINDOWS_DOMAIN_FORMAT.getName())) {
            format = JBossSAMLURIConstants.NAMEID_FORMAT_WINDOWS_DOMAIN_NAME.get();
            issuer = ".NotValidWindowsDomain.QualifierName?";
        }

        return SAMLAssertionFactory.createNameID(format, null, issuer);
    }

    /**
     * <p>getSubjectType.</p>
     *
     * @param context   a {@link org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext} object.
     * @param principal a {@link java.security.Principal} object.
     * @return a {@link org.picketlink.identity.federation.sam l.v2.assertion.SubjectType} object.
     */
    protected SubjectType getSubjectType(WSTrustRequestContext context, Principal principal) {

        // create a subject using the caller principal or on-behalf-of principal.
        String subjectName = principal == null ? "ANONYMOUS" : principal.getName();
        NameIDType nameID = SAMLAssertionFactory
                .createNameID(null, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", subjectName);

        return SAMLAssertionFactory.createSubject(nameID, getSubjectConfirmationType(context, principal));
    }

    /**
     * <p>getSubjectConfirmationType.</p>
     *
     * @param context   a {@link org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext} object.
     * @param principal a {@link java.security.Principal} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType} object.
     */
    protected SubjectConfirmationType getSubjectConfirmationType(WSTrustRequestContext context, Principal principal) {
        String confirmationMethod = assertionProperties.getProperty(AssertionProperties.Keys.SUBJECT_CONFIRMATION_METHOD);
        return SAMLAssertionFactory.createSubjectConfirmation(null, confirmationMethod, null);
    }

    /**
     * <p>postDomModification.</p>
     *
     * @param assertionElement a {@link org.w3c.dom.Element} object.
     * @param principal        a {@link java.security.Principal} object.
     * @return a {@link org.w3c.dom.Element} object.
     */
    protected Element postDomModification(Element assertionElement, Principal principal) {

        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_CONFIRMATION.getName())) {
            removeElement(assertionElement, SAML2_NS, "SubjectConfirmation");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_CONFIRMATION_DATA.getName())) {
            removeElement(assertionElement, SAML2_NS, "SubjectConfirmationData");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_CONFIRMATION_KEYINFO.getName())) {
            removeElement(assertionElement, XMLDSIG_NS, "KeyInfo");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_CONF_RSA_PUBLIC_KEY_EXPONENT.getName())) {
            removeElement(assertionElement, XMLDSIG_NS, "Exponent");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_SUBJECT_CONF_RSA_PUBLIC_KEY_MODULUS.getName())) {
            updateTextElement(assertionElement, XMLDSIG_NS, "Modulus", "testModulus");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_SUBJECT_CONF_RSA_PUBLIC_KEY_EXPONENT.getName())) {
            updateTextElement(assertionElement, XMLDSIG_NS, "Exponent", "testExponent");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_VERSION.getName())) {
            updateAttributeValueFromAssertionElement(assertionElement, "Version", "1.9");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_VERSION.getName())) {
            removeAttributeFromAssertionElement(assertionElement, "Version");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_ID.getName())) {
            removeAttributeFromAssertionElement(assertionElement, "ID");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_ID.getName())) {
            updateAttributeValueFromAssertionElement(assertionElement, "ID", "testID");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_ISSUEINSTANT.getName())) {
            removeAttributeFromAssertionElement(assertionElement, "IssueInstant");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_ISSUEINSTANT.getName())) {
            updateAttributeValueFromAssertionElement(assertionElement, "IssueInstant", "testIssueInstant");
        }
        if (principal.getName().equals(AssertionProfile.LATE_ISSUEINSTANT.getName())) {
            updateAttributeValueFromAssertionElement(assertionElement, "IssueInstant", "2117-06-16T14:03:18.064Z");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_ISSUER.getName())) {
            removeElement(assertionElement, SAML2_NS, "Issuer");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT.getName())) {
            removeElement(assertionElement, SAML2_NS, "Subject");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_NAMEID.getName())) {
            removeElement(assertionElement, SAML2_NS, "NameID");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_SUBJECT_CONFIRMATION_METHOD.getName())) {
            removeAttribute(assertionElement, SAML2_NS, "SubjectConfirmation", "Method");
        }
        if (principal.getName().equals(AssertionProfile.INVALID_SUBJECT_NAMEID_FORMAT.getName())) {
            updateAttribute(assertionElement, SAML2_NS, "NameID", "Format", "testFormat");
        }
        if (principal.getName().equals(AssertionProfile.MISSING_ISSUER_FORMAT.getName())) {
            removeAttribute(assertionElement, SAML2_NS, "Issuer", "Format");
        }


        return assertionElement;
    }

    /**
     * <p>updateAttribute.</p>
     *
     * @param assertionElement       a {@link org.w3c.dom.Element} object.
     * @param namespace              a {@link java.lang.String} object.
     * @param selectedElementName    a {@link java.lang.String} object.
     * @param selectedAttributeName  a {@link java.lang.String} object.
     * @param selectedAttributeValue a {@link java.lang.String} object.
     */
    protected void updateAttribute(Element assertionElement, String namespace, String selectedElementName,
                                   String selectedAttributeName, String selectedAttributeValue) {
        NodeList nodeList = assertionElement
                .getElementsByTagNameNS(namespace, selectedElementName);
        if (nodeList.getLength() > 0) {
            Attr attribute = (Attr) nodeList.item(0).getAttributes().getNamedItem(selectedAttributeName);
            if (attribute != null) {
                attribute.setNodeValue(selectedAttributeValue);
            } else {
                logger.warn(selectedAttributeName + " is not present in assertion !");
            }
        } else {
            logger.warn("Unable to find " + selectedElementName + " in this assertion !");
        }
    }

    /**
     * <p>updateAttributeValueFromAssertionElement.</p>
     *
     * @param assertionElement       a {@link org.w3c.dom.Element} object.
     * @param selectedAttributeName  a {@link java.lang.String} object.
     * @param selectedAttributeValue a {@link java.lang.String} object.
     */
    protected void updateAttributeValueFromAssertionElement(Element assertionElement, String selectedAttributeName,
                                                            String selectedAttributeValue) {
        Attr attribute = assertionElement
                .getAttributeNode(selectedAttributeName);
        if (attribute != null) {
            attribute.setNodeValue(selectedAttributeValue);
        } else {
            logger.warn(selectedAttributeName + " is not present in assertion !");
        }
    }

    /**
     * <p>removeAttributeFromAssertionElement.</p>
     *
     * @param assertionElement    a {@link org.w3c.dom.Element} object.
     * @param selectedElementName a {@link java.lang.String} object.
     */
    protected void removeAttributeFromAssertionElement(Element assertionElement, String selectedElementName) {
        Attr attribute = assertionElement
                .getAttributeNode(selectedElementName);
        if (attribute != null) {
            assertionElement.getAttributes().removeNamedItem(attribute.getName());
        } else {
            logger.warn("Unable to remove " + selectedElementName + " in this assertion !");
        }
    }

    /**
     * <p>removeAttribute.</p>
     *
     * @param assertionElement      a {@link org.w3c.dom.Element} object.
     * @param namespace             a {@link java.lang.String} object.
     * @param selectedElementName   a {@link java.lang.String} object.
     * @param selectedAttributeName a {@link java.lang.String} object.
     */
    protected void removeAttribute(Element assertionElement, String namespace, String selectedElementName,
                                   String selectedAttributeName) {
        NodeList nodeList = assertionElement
                .getElementsByTagNameNS(namespace, selectedElementName);
        if (nodeList.getLength() > 0) {
            Attr attribute = (Attr) nodeList.item(0).getAttributes().getNamedItem(selectedAttributeName);

            if (attribute != null) {
                nodeList.item(0).getAttributes().removeNamedItem(attribute.getName());
            } else {
                logger.warn("Unable to remove " + selectedAttributeName + " in " + selectedElementName + " !");
            }
        } else {
            logger.warn("Unable to find " + selectedElementName + " in this assertion !");
        }
    }

    /**
     * <p>removeElement.</p>
     *
     * @param assertionElement    a {@link org.w3c.dom.Element} object.
     * @param namespace           a {@link java.lang.String} object.
     * @param selectedElementName a {@link java.lang.String} object.
     */
    protected void removeElement(Element assertionElement, String namespace, String selectedElementName) {
        NodeList nodeList = assertionElement
                .getElementsByTagNameNS(namespace, selectedElementName);
        if (nodeList.getLength() > 0) {
            nodeList.item(0).getParentNode().removeChild(nodeList.item(0));
        } else {
            logger.warn("Unable to remove " + selectedElementName + " in this assertion !");
        }
    }

    /**
     * <p>updateTextElement.</p>
     *
     * @param assertionElement    a {@link org.w3c.dom.Element} object.
     * @param namespace           a {@link java.lang.String} object.
     * @param selectedElementName a {@link java.lang.String} object.
     * @param newValue            a {@link java.lang.String} object.
     */
    protected void updateTextElement(Element assertionElement, String namespace, String selectedElementName,
                                     String newValue) {
        NodeList nodeList = assertionElement
                .getElementsByTagNameNS(namespace, selectedElementName);
        if (nodeList.getLength() > 0) {
            nodeList.item(0).setTextContent(newValue);
        } else {
            logger.warn("Unable to update " + selectedElementName + " in this assertion !");
        }
    }

    /**
     * <p>Getter for the field <code>domain</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    protected String getDomain() {
        if (domain == null || domain.isEmpty()) {
            domain = assertionProperties.getProperty(AssertionProperties.Keys.DOMAIN);
        }
        return domain;
    }

    protected String getRole(Element assertionElement) {
        NodeList nodeListRole = assertionElement.getElementsByTagNameNS("*", "Role");
        return nodeListRole.item(0).getAttributes().getNamedItem("displayName").getNodeValue();
    }

    protected String getPurposeOfUse(Element assertionElement) {
        NodeList nodeListPurposeofuse = assertionElement.getElementsByTagNameNS("*", "PurposeOfUse");
        return nodeListPurposeofuse.item(0).getAttributes().getNamedItem("displayName").getNodeValue();
    }

    protected boolean isResourceId(Element assertionElement) {
        return isAttributeNamePresent(assertionElement, "urn:oasis:names:tc:xacml:2.0:resource:resource-id");
    }

    protected boolean isDocId(Element assertionElement) {
        return isAttributeNamePresent(assertionElement, "urn:ihe:iti:bppc:2007:docid");
    }

    private boolean isAttributeNamePresent(Element assertionElement, String attributeName) {
        boolean attributeNamePresent = false;
        NodeList nodeListAttributeValue = assertionElement.getElementsByTagNameNS("*", "Attribute");
        for (int i = 0; i < nodeListAttributeValue.getLength(); i++) {
            if (nodeListAttributeValue.item(i).getAttributes().getNamedItem("Name").getNodeValue()
                    .equals(attributeName)) {
                attributeNamePresent = true;
            }
        }
        return attributeNamePresent;
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
