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
package net.ihe.gazelle.sts.wstrust.sequoia;

import net.ihe.gazelle.sts.config.AssertionProperties;
import net.ihe.gazelle.sts.config.SequoiaAssertionProperties;
import net.ihe.gazelle.sts.constants.AssertionProfile;
import net.ihe.gazelle.sts.saml.IHESAMLUtil;
import net.ihe.gazelle.sts.wstrust.ihe.IHESAML20TokenProvider;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.StatementUtil;
import org.picketlink.identity.federation.core.wstrust.SecurityToken;
import org.picketlink.identity.federation.core.wstrust.StandardSecurityToken;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime;
import org.picketlink.identity.federation.saml.v2.assertion.ActionType;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.DecisionType;
import org.picketlink.identity.federation.saml.v2.assertion.EvidenceType;
import org.picketlink.identity.federation.saml.v2.assertion.KeyInfoConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.RequestedReferenceType;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.wss.secext.KeyIdentifierType;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <p>
 * A {@code SecurityTokenProvider} implementation that handles WS-Trust SAML 2.0 token requests for Sequoia project.
 * </p>
 *
 * @author ceoche
 * @version $Id: $Id
 */
public class SequoiaSAML20TokenProvider extends IHESAML20TokenProvider {

    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
     * issueToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
     */

    /**
     * {@inheritDoc}
     */
    @Override
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

        // Issuer
        NameIDType issuerID = getIssuerNameIDType(context, principal);

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

        // Subject
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

        // create an Authz Decision Statement only for Assertion profile ACP_VALID
        if (AssertionProfile.ACP_VALID.getName().equals(principal.getName())) {
            String resource = appliesTo != null ? WSTrustUtil.parseAppliesTo(appliesTo) : "";
            DecisionType decision = principal.getName()
                    .equals(AssertionProfile.SECOND_ROLE.getName()) ? DecisionType.DENY : DecisionType.PERMIT;
            AssertionType authzDecisionAssertion = createAuthzDecisionAssertion(context, issuerID, lifetime, conditions);
            EvidenceType evidence = new EvidenceType();
            evidence.addEvidence(new EvidenceType.ChoiceType(authzDecisionAssertion));
            AuthzDecisionStatementType authzDecisionStatement = createAuthzDecisionStatementType(resource, decision,
                    evidence, null);
            statements.add(authzDecisionStatement);
        }

        // create the SAML assertion.
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

        if (assertion != null) {
            // check if the assertion has been canceled before.
            if (this.revocationRegistry.isRevoked(SAMLUtil.SAML2_TOKEN_TYPE, assertion.getID())) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: assertion with id " + assertion.getID() + " has been canceled";
            }

            /*
             * - ASSERTION VALIDATION WITH XUA TESTS CHARACTERISTICS -
             * I. The Audience element shall contain an URI identifying the X-Service Provider. It may contain other Audience URI identifying the
             * Affinity domain.
             * II. The Conditions element shall contain a valid lifetime period
             * III. The AutnContextClassRef shall be defined
             * IV. The attribute Role shall be defined
             * V. The attribute PurposeOfUse shall be defined
             */

            // I. The Audience element shall contain an URI identifying the X-Service Provider. It may contain other Audience URI identifying the
            // Affinity domain.
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


            /*
            MLB 07-05-2023 Issue confirmed as still relevant. Not yet repaired by IHE services.

            This next segment of code ASSUMES the AuthnStatement is the next element in the XML,
            but that is not always the case. Indeed, it is NOT the case with Epic.

            MLB 2022-04-20 There is an issue here in that the order of the elements is assumed incorrectly to be a sequence.
            This causes a fault in EPIC system. See JIRA SEQUOIA-423

            https://gazelle.ihe.net/jira/servicedesk/customer/portal/15/SEQUOIA-423

             */
            // III. The AutnContextClassRef shall be defined
            try {
                logger.debug("MLB DEBUG 2023: Processing AuthnContextClassRef...");
                Object[] tab_statements = assertion.getStatements().toArray();
                logger.debug("MLB DEBUG 2023: Assertion Object Array" + Arrays.toString(tab_statements));
                /* String value = (((AuthnStatementType) tab_statements[0]).getAuthnContext().getSequence().getClassRef()
                        .getValue()).toString();
                if (value.equals("urn:oasis:names:tc:SAML:2.0:ac:classes:Invalid")) {
                    code = WSTrustConstants.STATUS_CODE_INVALID;
                    reason = "Validation failure: invalid AuthnStatement parameter";
                } */

            } catch (Exception ce) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: unable to verify AuthContextClassRef value: " + ce.getMessage();
            }

            // IV. The attribute Role shall be defined
            String currentRole = getRole(assertionElement);
            if (currentRole == null || currentRole.isEmpty()) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: Role attribute not present";
                logger.error(reason);
            }

            // V. The attribute PurposeOfUse shall be defined
            String currentPurposeOfUse = getPurposeOfUse(assertionElement);
            if (currentPurposeOfUse == null || currentPurposeOfUse.isEmpty()) {
                code = WSTrustConstants.STATUS_CODE_INVALID;
                reason = "Validation failure: PurposeOfUse attribute not present";
                logger.error(reason);
            }
        }

        // construct the status and set it on the request context.
        StatusType status = new StatusType();
        status.setCode(code);
        status.setReason(reason);
        context.setStatus(status);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected AssertionProperties provideAssertionProperties() {
        return new SequoiaAssertionProperties();
    }

    /**
     * Create an Authorization Decision Statement Type.
     * Copied from {@link org.picketlink.identity.federation.api.saml.v2.response.SAML2Response}.
     *
     * @param resource a {@link java.lang.String} object.
     * @param decision a {@link org.picketlink.identity.federation.saml.v2.assertion.DecisionType} object.
     * @param evidence a {@link org.picketlink.identity.federation.saml.v2.assertion.EvidenceType} object.
     * @param actions  a {@link org.picketlink.identity.federation.saml.v2.assertion.ActionType} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType} object.
     */
    protected AuthzDecisionStatementType createAuthzDecisionStatementType(String resource, DecisionType decision,
                                                                          EvidenceType evidence,
                                                                          ActionType... actions) {
        AuthzDecisionStatementType authzDecST = new AuthzDecisionStatementType();
        authzDecST.setResource(resource);
        authzDecST.setDecision(decision);
        if (evidence != null) {
            authzDecST.setEvidence(evidence);
        }

        if (actions != null) {
            authzDecST.getAction().addAll(Arrays.asList(actions));
        }

        return authzDecST;
    }

    /**
     * <p>createAuthzDecisionAssertion.</p>
     *
     * @param context    a {@link org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext} object.
     * @param issuerID   a {@link org.picketlink.identity.federation.saml.v2.assertion.NameIDType} object.
     * @param lifetime   a {@link org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime} object.
     * @param conditions a {@link org.picketlink.identity.federation.saml.v2.assertion.ConditionsType} object.
     * @return a {@link org.picketlink.identity.federation.saml.v2.assertion.AssertionType} object.
     */
    protected AssertionType createAuthzDecisionAssertion(WSTrustRequestContext context, NameIDType issuerID,
                                                         Lifetime lifetime,
                                                         ConditionsType conditions) {

        // generate an id for the new assertion.
        String assertionID = IDGenerator.create("ID_");

        // generate AttributeStatement for AuthzDesicion
        List<StatementAbstractType> statements = new ArrayList<StatementAbstractType>();

        AttributeStatementType attributeStatement = new AttributeStatementType();

        AttributeType accessConsentPolicyAttribute = new AttributeType("AccessConsentPolicy");
        accessConsentPolicyAttribute.setNameFormat("http://www.hhs.gov/healthit/nhin");
        accessConsentPolicyAttribute.addAttributeValue("urn:oid:1.2.3.4");

        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(accessConsentPolicyAttribute));

        AttributeType instanceAccessConsentPolicyAttribute = new AttributeType("InstanceAccessConsentPolicy");
        instanceAccessConsentPolicyAttribute.setNameFormat("http://www.hhs.gov/healthit/nhin");
        instanceAccessConsentPolicyAttribute.addAttributeValue("urn:oid:1.2.3.4.123456789");
        attributeStatement.addAttribute(new AttributeStatementType.ASTChoiceType(instanceAccessConsentPolicyAttribute));

        statements.add(attributeStatement);

        // create assertion
        Principal principal = context.getCallerPrincipal();
        SubjectType suject = getSubjectType(context, principal);
        return SAMLAssertionFactory.createAssertion(assertionID, issuerID, lifetime.getCreated(),
                conditions, suject, statements);

    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected SubjectType getSubjectType(WSTrustRequestContext context, Principal principal) {

        // create a subject using the caller principal or on-behalf-of principal.
        String subjectName = principal == null ? "ANONYMOUS" : principal.getName();
        NameIDType nameID = SAMLAssertionFactory
                .createNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", null,
                        subjectName.toLowerCase() + "@" + getDomain());

        return SAMLAssertionFactory.createSubject(nameID, getSubjectConfirmationType(context, principal));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected SubjectConfirmationType getSubjectConfirmationType(WSTrustRequestContext context, Principal principal) {

        String confirmationMethod = assertionProperties.getProperty(AssertionProperties.Keys.SUBJECT_CONFIRMATION_METHOD);

        if (SAMLUtil.SAML2_HOLDER_OF_KEY_URI.equals(confirmationMethod)) {
            NameIDType nameID = SAMLAssertionFactory
                    .createNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", null,
                            context.getTokenIssuer());
            KeyInfoConfirmationDataType keyInfoConfirmationDataType = SAMLAssertionFactory
                    .createKeyInfoConfirmation(context.getProofTokenInfo());
            SubjectConfirmationType subjectConfirmationType = SAMLAssertionFactory
                    .createSubjectConfirmation(nameID, confirmationMethod, keyInfoConfirmationDataType);
            return subjectConfirmationType;
        } else {
            return super.getSubjectConfirmationType(context, principal);
        }
    }

    protected String getRole(Element assertionElement) {
        NodeList nodeListRole = assertionElement.getElementsByTagNameNS("*", "Role");
        return nodeListRole.item(0).getAttributes().getNamedItem("code").getNodeValue();
    }

    protected String getPurposeOfUse(Element assertionElement) {
        NodeList nodeListPurposeofuse = assertionElement.getElementsByTagNameNS("*", "PurposeOfUse");
        return nodeListPurposeofuse.item(0).getAttributes().getNamedItem("code").getNodeValue();
    }

}
