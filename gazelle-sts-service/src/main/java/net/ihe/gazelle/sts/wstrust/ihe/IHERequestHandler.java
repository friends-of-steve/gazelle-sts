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

import net.ihe.gazelle.atna.action.pki.ws.CertificateValidatorErrorTrace;
import net.ihe.gazelle.atna.action.pki.ws.CertificateValidatorResult;
import net.ihe.gazelle.pki.ws.CertificateValidator;
import net.ihe.gazelle.sts.config.*;
import net.ihe.gazelle.sts.constants.AssertionProfile;
import org.opensaml.xml.signature.DSAKeyValue;
import org.opensaml.xml.signature.RSAKeyValue;
import org.picketlink.common.PicketLinkLogger;
import org.picketlink.common.PicketLinkLoggerFactory;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ParsingException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.fed.WSTrustException;
import org.picketlink.common.util.Base64;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.SystemPropertiesUtil;
import org.picketlink.identity.federation.core.saml.v1.SAML11Constants;
import org.picketlink.identity.federation.core.saml.v2.util.SignatureUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.core.util.XMLEncryptionUtil;
import org.picketlink.identity.federation.core.util.XMLSignatureUtil;
import org.picketlink.identity.federation.core.wstrust.ClaimsProcessor;
import org.picketlink.identity.federation.core.wstrust.STSConfiguration;
import org.picketlink.identity.federation.core.wstrust.SecurityToken;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.BinarySecretType;
import org.picketlink.identity.federation.ws.trust.ClaimsType;
import org.picketlink.identity.federation.ws.trust.ComputedKeyType;
import org.picketlink.identity.federation.ws.trust.EntropyType;
import org.picketlink.identity.federation.ws.trust.RequestedProofTokenType;
import org.picketlink.identity.federation.ws.trust.RequestedSecurityTokenType;
import org.picketlink.identity.federation.ws.trust.RequestedTokenCancelledType;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.picketlink.identity.xmlsec.w3.xmldsig.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.Duration;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>
 * Default implementation of the {@code WSTrustRequestHandler} interface. It creates the request context containing the
 * original
 * WS-Trust request as well as any information that may be relevant to the token processing, and delegates the actual
 * token
 * handling processing to the appropriate {@code SecurityTokenProvider}.
 * </p>
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author <a href="mailto:alessio.soldano@jboss.com">Alessio Soldano</a>
 * @version $Id: $Id
 */
public class IHERequestHandler implements WSTrustRequestHandler {

    /**
     * Constant <code>SAML2_NS="urn:oasis:names:tc:SAML:2.0:assertion"</code>
     */
    protected static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    /**
     * Constant <code>XMLDSIG_NS="http://www.w3.org/2000/09/xmldsig#"</code>
     */
    protected static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final PicketLinkLogger logger = PicketLinkLoggerFactory.getLogger();
    private static final long HOUR24_MILLI = 86400000;
    private static long KEY_SIZE = 128;
    protected STSConfiguration configuration;

    private boolean base64EncodeSecretKey = Boolean.parseBoolean(
            SystemPropertiesUtil.getSystemProperty(GeneralConstants.BASE64_ENCODE_WSTRUST_SECRET_KEY, "false"));

    /**
     * Setup the ID attribute in the provided node if it's a SAML Assertion element.
     *
     * @param node The node representing the SAML Assertion
     * @return A reference to the correct ID
     */
    private static String setupIDAttribute(Node node) {
        if (node instanceof Element) {
            Element assertion = (Element) node;
            if (assertion.getLocalName().equals("Assertion")) {
                if (assertion.getNamespaceURI().equals(WSTrustConstants.SAML2_ASSERTION_NS) && assertion
                        .hasAttribute("ID")) {
                    assertion.setIdAttribute("ID", true);
                    return "#" + assertion.getAttribute("ID");
                } else if (assertion.getNamespaceURI().equals(SAML11Constants.ASSERTION_11_NSURI)
                        && assertion.hasAttribute(SAML11Constants.ASSERTIONID)) {
                    assertion.setIdAttribute(SAML11Constants.ASSERTIONID, true);
                    return "#" + assertion.getAttribute(SAML11Constants.ASSERTIONID);
                }
            }
        }
        return "";
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler#initialize(
     * org.picketlink.identity.federation.core.wstrust.STSConfiguration)
     */

    /**
     * {@inheritDoc}
     */
    public void initialize(STSConfiguration configuration) {
        this.configuration = configuration;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler#issue(
     * org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken, java.security.Principal)
     */

    /**
     * {@inheritDoc}
     */
    public RequestSecurityTokenResponse issue(RequestSecurityToken request, Principal callerPrincipal)
            throws WSTrustException {

        AssertionProperties assertionProperties = provideAssertionProperties();
        logger.info("Issuing token for principal " + callerPrincipal);

        // SecurityTokenProvider provider = null;

        // first try to obtain the security token provider using the applies-to contents.
        AppliesTo appliesTo = request.getAppliesTo();
        X509Certificate providerCertificate = null;
        PublicKey providerPublicKey = null;
        if (appliesTo != null) {
            String serviceName = WSTrustUtil.parseAppliesTo(appliesTo);

            if (serviceName != null) {
                String tokenTypeFromServiceName = configuration.getTokenTypeForService(serviceName);

                if (request.getTokenType() == null && tokenTypeFromServiceName != null) {
                    request.setTokenType(URI.create(tokenTypeFromServiceName));
                }

                providerCertificate = this.configuration.getServiceProviderCertificate(serviceName);

                if (providerCertificate != null) {
                    providerPublicKey = providerCertificate.getPublicKey();
                }
            }
        }

        // create the request context and delegate token generation to the provider.
        WSTrustRequestContext requestContext = new WSTrustRequestContext(request, callerPrincipal);

        requestContext.setTokenIssuer(getIssuer(callerPrincipal, assertionProperties));

        /*
         * ------------------------------
         * Created by IHE-Europe (fgate)
         * ------------------------------
         * - CONDITIONS ELEMENT -
         * Get the LifeTime value from the file parameters.assertion
         */
        if (request.getLifetime() == null) {
            // if no lifetime has been specified, use the configured timeout value.

            long lifetimetoken = this.configuration.getIssuedTokenTimeout();
            request.setLifetime(WSTrustUtil.createDefaultLifetime(lifetimetoken));
        }

        //delay for not yet valid assertion
        if (callerPrincipal.getName().equals(AssertionProfile.NOT_YET_VALID.getName())) {
            Duration duration = null;
            try {
                duration = XMLTimeUtil.newDatatypeFactory().newDuration(HOUR24_MILLI);
                request.getLifetime().getCreated().add(duration);
                request.getLifetime().getExpires().add(duration);
            } catch (DatatypeConfigurationException e) {
                logger.error("Error while creating not-yet-valid token: " + e.getMessage());
            }
        }
        //set ahead for expired assertion
        if (callerPrincipal.getName().equals(AssertionProfile.EXPIRED.getName())) {
            Duration duration = null;
            try {
                duration = XMLTimeUtil.newDatatypeFactory().newDuration(-HOUR24_MILLI);
                request.getLifetime().getCreated().add(duration);
                request.getLifetime().getExpires().add(duration);
            } catch (DatatypeConfigurationException e) {
                logger.error("Error while creating expired token: " + e.getMessage());
            }
        }

        requestContext.setServiceProviderPublicKey(providerPublicKey);

        // process the claims if needed.
        if (request.getClaims() != null) {
            ClaimsType claims = request.getClaims();
            ClaimsProcessor processor = this.configuration.getClaimsProcessor(claims.getDialect());
            // if there is a processor, process the claims and set the resulting attributes in the context.
            if (processor != null) {
                requestContext.setClaimedAttributes(processor.processClaims(claims, callerPrincipal));
            } else if (logger.isDebugEnabled()) {
                logger.debug(
                        "Claims have been specified in the request but no processor was found for dialect " + claims
                                .getDialect());
            }
        }

        // get the OnBehalfOf principal, if one has been specified.
        if (request.getOnBehalfOf() != null) {
            Principal onBehalfOfPrincipal = WSTrustUtil.getOnBehalfOfPrincipal(request.getOnBehalfOf());
            requestContext.setOnBehalfOfPrincipal(onBehalfOfPrincipal);
        }

        // get the key type and size from the request, setting default values if not specified.
        URI keyType = request.getKeyType();
        if (keyType == null) {
            logger.debug("No key type could be found in the request. Using the default BEARER type.");
            keyType = URI.create(WSTrustConstants.KEY_TYPE_BEARER);
            request.setKeyType(keyType);
        }
        long keySize = request.getKeySize();
        if (keySize == 0) {
            logger.debug("No key size could be found in the request. Using the default size. (" + KEY_SIZE + ")");
            keySize = KEY_SIZE;
            request.setKeySize(keySize);
        }

        // get the key wrap algorithm.
        URI keyWrapAlgo = request.getKeyWrapAlgorithm();

        // create proof-of-possession token and server entropy (if needed).
        RequestedProofTokenType requestedProofToken = null;
        EntropyType serverEntropy = null;

        if (WSTrustConstants.KEY_TYPE_SYMMETRIC.equalsIgnoreCase(keyType.toString())) {
            // symmetric key case: if client entropy is found, compute a key. If not, generate a new key.
            requestedProofToken = new RequestedProofTokenType();

            byte[] serverSecret = WSTrustUtil.createRandomSecret((int) keySize / 8);
            BinarySecretType serverBinarySecret = new BinarySecretType();
            serverBinarySecret.setType(WSTrustConstants.BS_TYPE_NONCE);
            serverBinarySecret.setValue(Base64.encodeBytes(serverSecret).getBytes());

            byte[] clientSecret = null;
            EntropyType clientEntropy = request.getEntropy();
            if (clientEntropy != null) {
                clientSecret = Base64.decode(new String(WSTrustUtil.getBinarySecret(clientEntropy)));
                serverEntropy = new EntropyType();
                serverEntropy.addAny(serverBinarySecret);
            }

            if (clientSecret != null && clientSecret.length != 0) {
                // client secret has been specified - combine it with the sts secret.
                requestedProofToken.add(new ComputedKeyType(WSTrustConstants.CK_PSHA1));
                byte[] combinedSecret = null;
                try {
                    if (base64EncodeSecretKey == true) {
                        combinedSecret = Base64
                                .encodeBytes(WSTrustUtil.P_SHA1(clientSecret, serverSecret, (int) keySize / 8))
                                .getBytes();
                    } else {
                        combinedSecret = WSTrustUtil.P_SHA1(clientSecret, serverSecret, (int) keySize / 8);
                    }
                } catch (Exception e) {
                    throw logger.wsTrustCombinedSecretKeyError(e);
                }
                requestContext.setProofTokenInfo(
                        WSTrustUtil.createKeyInfo(combinedSecret, providerPublicKey, keyWrapAlgo, providerCertificate));
            } else {
                // client secret has not been specified - use the sts secret only.
                requestedProofToken.add(serverBinarySecret);
                requestContext.setProofTokenInfo(WSTrustUtil.createKeyInfo(serverSecret, providerPublicKey,
                        keyWrapAlgo, providerCertificate));
            }
        } else if (WSTrustConstants.KEY_TYPE_PUBLIC.equalsIgnoreCase(keyType.toString())) {
            // try to locate the client cert in the keystore using the caller principal as the alias.
            Certificate certificate = this.configuration.getCertificate(callerPrincipal.getName());
            if (certificate != null) {
                requestContext.setProofTokenInfo(WSTrustUtil.createKeyInfo(certificate));
            }
            // if no certificate was found in the keystore, check the UseKey contents.
            else if (request.getUseKey() != null) {
                UseKeyType useKeyType = request.getUseKey();
                List<Object> theList = useKeyType.getAny();
                for (Object value : theList) {
                    if (value instanceof Element) {
                        Element keyElement = (Element) value;
                        String elementName = (keyElement).getLocalName();
                        // if the specified key is a X509 certificate we must insert it into a X509Data element.
                        if (elementName.equals("X509Certificate")) {
                            X509DataType data = new X509DataType();
                            data.add(value);
                            value = data;
                        } else if (elementName.equals("KeyValue")) {
                            KeyValueType keyValue = null;
                            Element child = DocumentUtil
                                    .getChildElement(keyElement, new QName(WSTrustConstants.XMLDSig.RSA_KEYVALUE));
                            if (child != null) {
                                try {
                                    keyValue = SignatureUtil.getRSAKeyValue(child);
                                } catch (ParsingException e) {
                                    throw logger.stsError(e);
                                }
                            }
                            if (keyValue == null && child == null) {
                                child = DocumentUtil
                                        .getChildElement(keyElement, new QName(WSTrustConstants.XMLDSig.DSA_KEYVALUE));
                                if (child != null) {
                                    try {
                                        keyValue = SignatureUtil.getDSAKeyValue(child);
                                    } catch (ParsingException e) {
                                        throw logger.stsError(e);
                                    }
                                }
                                value = keyValue;
                            }
                        }
                        KeyInfoType keyInfo = new KeyInfoType();
                        keyInfo.addContent(value);
                        requestContext.setProofTokenInfo(keyInfo);
                    } else if (value instanceof KeyInfoType) {
                        requestContext.setProofTokenInfo((KeyInfoType) value);
                    } else {
                        throw new WSTrustException(logger.unsupportedType(value.toString()));
                    }
                }
            } else {
                throw logger.wsTrustClientPublicKeyError();
            }
        }

        // issue the security token using the constructed context.
        try {
            if (request.getTokenType() != null) {
                requestContext.setTokenType(request.getTokenType().toString());
            }
            PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
            sts.initialize(configuration);
            sts.issueToken(requestContext);
        } catch (ProcessingException e) {
            throw logger.stsError(e);
        }

        if (requestContext.getSecurityToken() == null) {
            throw new WSTrustException(logger.nullValueError("Token issued by STS"));
        }

        // construct the ws-trust security token response.
        RequestedSecurityTokenType requestedSecurityToken = new RequestedSecurityTokenType();

        SecurityToken contextSecurityToken = requestContext.getSecurityToken();
        if (contextSecurityToken == null) {
            throw new WSTrustException(logger.nullValueError("Security Token from context"));
        }

        requestedSecurityToken.add(contextSecurityToken.getTokenValue());

        RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
        if (request.getContext() != null) {
            response.setContext(request.getContext());
        }

        response.setTokenType(request.getTokenType());
        response.setLifetime(request.getLifetime());
        response.setAppliesTo(appliesTo);
        response.setKeySize(keySize);
        response.setKeyType(keyType);
        response.setRequestedSecurityToken(requestedSecurityToken);

        if (requestedProofToken != null) {
            response.setRequestedProofToken(requestedProofToken);
        }
        if (serverEntropy != null) {
            response.setEntropy(serverEntropy);
        }

        // set the attached and unattached references.
        if (requestContext.getAttachedReference() != null) {
            response.setRequestedAttachedReference(requestContext.getAttachedReference());
        }
        if (requestContext.getUnattachedReference() != null) {
            response.setRequestedUnattachedReference(requestContext.getUnattachedReference());
        }

        return response;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler#renew(
     * org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken, java.security.Principal)
     */

    /**
     * {@inheritDoc}
     */
    public RequestSecurityTokenResponse renew(RequestSecurityToken request, Principal callerPrincipal)
            throws WSTrustException {
        // first validate the provided token signature to make sure it has been issued by this STS and hasn't been
        // tempered.
        AssertionProperties assertionProperties = provideAssertionProperties();
        logger.trace("Validating token for renew request " + request.getContext());

        if (request.getRenewTargetElement() == null) {
            throw new WSTrustException(logger.nullValueError("renew target"));
        }

        Node securityToken = request.getRenewTargetElement().getFirstChild();
        if (securityToken == null) {
            throw new WSTrustException(logger.nullValueError("security token"));
        }

        /*
         * SecurityTokenProvider provider = this.configuration.getProviderForTokenElementNS(securityToken.getLocalName(),
         * securityToken.getNamespaceURI()); if (provider == null) throw new
         * WSTrustException("No SecurityTokenProvider configured for " + securityToken.getNamespaceURI() + ":" +
         * securityToken.getLocalName());
         */

        setupIDAttribute(securityToken);

        if (this.configuration.signIssuedToken()) {
            WSTrustException validationException = null;
            try {
                //Verify signature validation
                boolean isSignatureValid = verifyIfSignatureIsValid(securityToken);
                if (isSignatureValid && ((GazelleSTSConfiguration) this.configuration).isIssuerTrustValidationEnabled()) {
                    verifyIfTokenIssuerIsTrusted(securityToken);
                }
            } catch (Exception e) {
                validationException = new WSTrustException(
                        logger.signatureInvalidError("Validation failure during renewal: " + e.getMessage(), e));
            }

            if (validationException != null) {
                throw validationException;
            }

        } else {
            logger.stsSecurityTokenSignatureNotVerified();
        }

        // set default values where needed.
        if (request.getLifetime() == null && this.configuration.getIssuedTokenTimeout() != 0) {
            // if no lifetime has been specified, use the configured timeout value.
            request.setLifetime(WSTrustUtil.createDefaultLifetime(this.configuration.getIssuedTokenTimeout()));
        }

        // create a context and dispatch to the proper security token provider for renewal.
        WSTrustRequestContext context = new WSTrustRequestContext(request, callerPrincipal);

        context.setTokenIssuer(getIssuer(callerPrincipal, assertionProperties));

        // if the renew request was made on behalf of another identity, get the principal of that identity.
        if (request.getOnBehalfOf() != null) {
            Principal onBehalfOfPrincipal = WSTrustUtil.getOnBehalfOfPrincipal(request.getOnBehalfOf());
            context.setOnBehalfOfPrincipal(onBehalfOfPrincipal);
        }
        try {
            if (securityToken != null) {
                String ns = securityToken.getNamespaceURI();

                context.setQName(new QName(ns, securityToken.getLocalName()));
            }
            PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
            sts.initialize(configuration);
            sts.renewToken(context);
            // provider.renewToken(context);
        } catch (ProcessingException e) {
            throw new WSTrustException(e.getMessage(), e);
        }

        // create the WS-Trust response with the renewed token.
        RequestedSecurityTokenType requestedSecurityToken = new RequestedSecurityTokenType();
        SecurityToken contextSecurityToken = context.getSecurityToken();
        if (contextSecurityToken == null) {
            throw new WSTrustException(logger.nullValueError("Security Token from context"));
        }
        requestedSecurityToken.add(contextSecurityToken.getTokenValue());

        RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
        if (request.getContext() != null) {
            response.setContext(request.getContext());
        }
        response.setTokenType(request.getTokenType());
        response.setLifetime(request.getLifetime());
        response.setRequestedSecurityToken(requestedSecurityToken);
        if (context.getAttachedReference() != null) {
            response.setRequestedAttachedReference(context.getAttachedReference());
        }
        if (context.getUnattachedReference() != null) {
            response.setRequestedUnattachedReference(context.getUnattachedReference());
        }
        return response;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler#validate(
     * org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken, java.security.Principal)
     */

    /**
     * {@inheritDoc}
     */
    public RequestSecurityTokenResponse validate(RequestSecurityToken request, Principal callerPrincipal)
            throws WSTrustException {

        logger.trace("Started validation for request " + request.getContext());

        if (request.getValidateTargetElement() == null) {
            throw new WSTrustException(
                    logger.nullValueError("request does not have a validate target. Unable to validate token"));
        }

        if (request.getTokenType() == null) {
            request.setTokenType(URI.create(WSTrustConstants.STATUS_TYPE));
        }

        Node securityToken = request.getValidateTargetElement().getFirstChild();
        if (securityToken == null) {
            throw new WSTrustException(logger.nullValueError("security token:Unable to validate token"));
        }

        setupIDAttribute(securityToken);

        WSTrustRequestContext context = new WSTrustRequestContext(request, callerPrincipal);
        // if the validate request was made on behalf of another identity, get the principal of that identity.
        if (request.getOnBehalfOf() != null) {
            Principal onBehalfOfPrincipal = WSTrustUtil.getOnBehalfOfPrincipal(request.getOnBehalfOf());
            context.setOnBehalfOfPrincipal(onBehalfOfPrincipal);
        }

        StatusType status = null;

        // validate the security token digital signature.
        if (this.configuration.signIssuedToken()) {
            try {
                if (logger.isTraceEnabled()) {
                    logger.trace("Going to validate signature for: " + DocumentUtil.getNodeAsString(securityToken));
                }
                // Verify the signature
                try {
                    boolean isSignatureValid = verifyIfSignatureIsValid(securityToken);
                    // Verify if token issuer is trusted
                    if (isSignatureValid && ((GazelleSTSConfiguration) this.configuration).isIssuerTrustValidationEnabled()) {
                        try {
                            verifyIfTokenIssuerIsTrusted(securityToken);
                        } catch (WSTrustException e) {
                            status = new StatusType();
                            status.setCode(WSTrustConstants.STATUS_CODE_INVALID);
                            StringBuilder sbErrors = new StringBuilder();
                            for (CertificateValidatorErrorTrace errorTrace : validateCertificate(getPemCertificateStringFromNode(securityToken)).getErrors()) {
                                sbErrors.append(errorTrace.getExceptionMessage());
                            }
                            status.setReason("Validation failure: " + sbErrors.toString());
                        }
                    }
                } catch (WSTrustException exception) {
                    status = new StatusType();
                    status.setCode(WSTrustConstants.STATUS_CODE_INVALID);
                    status.setReason("Validation failure: digital signature is invalid");
                }
            } catch (Exception e) {
                status = new StatusType();
                status.setCode(WSTrustConstants.STATUS_CODE_INVALID);
                status.setReason("Validation failure: unable to verify digital signature: " + e.getMessage());
            }
        } else {
            logger.stsSecurityTokenSignatureNotVerified();
        }

        // if the signature is valid, then let the provider perform any additional validation checks.
        if (status == null) {
            logger.trace("Delegating token validation to token provider. Token NS: " + securityToken
                    .getNamespaceURI() + " ::LocalName: " + securityToken.getLocalName());
            try {
                if (securityToken != null) {
                    context.setQName(new QName(securityToken.getNamespaceURI(), securityToken.getLocalName()));
                }
                PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
                sts.initialize(configuration);
                sts.validateToken(context);
            } catch (ProcessingException e) {
                throw logger.stsError(e);
            }
            status = context.getStatus();
        }

        // construct and return the response.
        RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
        if (request.getContext() != null) {
            response.setContext(request.getContext());
        }
        response.setTokenType(request.getTokenType());
        response.setStatus(status);

        return response;
    }

    private boolean verifyIfSignatureIsValid(Node securityToken) throws ConfigurationException, ProcessingException, MarshalException, XMLSignatureException, WSTrustException {
        Document tokenDocument = DocumentUtil.createDocument();
        Node importedNode = tokenDocument.importNode(securityToken, true);
        tokenDocument.appendChild(importedNode);
        XMLSignatureUtil.propagateIDAttributeSetup(securityToken, tokenDocument.getDocumentElement());

        PublicKey issuerPublicKey = getPublicKeyFromDocument(tokenDocument);
        if (!XMLSignatureUtil.validate(tokenDocument, issuerPublicKey)) {
            throw new WSTrustException(logger.signatureInvalidError(
                    "Validation failure during renewal: digital signature is invalid", null));
        } else {
            return true;
        }
    }

    private void verifyIfTokenIssuerIsTrusted(Node securityToken) throws Exception {
        // Verify if token issuer is trusted
        String issuerPemCertificate = getPemCertificateStringFromNode(securityToken);
        if (issuerPemCertificate != null) {
            CertificateValidatorResult result = validateCertificate(issuerPemCertificate);
            boolean isTrusted = CertificateValidator.isTrusted(result);
            if (!isTrusted) {
                throw new WSTrustException(
                        logger.signatureInvalidError("Validation failure during renewal: " + result.getErrors(),
                                null));
            }
        } else {
            //TODO Validate trust of the RSAKeyValue [STS-27]
        }
    }

    private CertificateValidatorResult validateCertificate(String issuerPemCertificate) throws Exception {
        CertificateValidator validator = ((GazelleSTSConfiguration) this.configuration)
                .getCertificateValidator();
        return validator.validate(issuerPemCertificate);
    }


    private PublicKey getPublicKeyFromDocument(Document tokenDocument) throws ProcessingException {
        X509Certificate x509Certificate = getX509CertificateFromTokenDocument(tokenDocument);
        if (x509Certificate != null) {
            return x509Certificate.getPublicKey();
        } else {
            RSAKeyValueType rsaKeyValueType = getRsaKeyValueFromTokenDocument(tokenDocument);
            if (rsaKeyValueType != null) {
                return rsaKeyValueType.convertToPublicKey();
            } else {
                DSAKeyValueType dsaKeyValueType = getDsaKeyValueFromTokenDocument(tokenDocument);
                if (dsaKeyValueType != null) {
                    return dsaKeyValueType.convertToPublicKey();
                } else {
                    throw logger.nullValueError("Cannot find X509Certificate element, RSAKeyValue element or DSAKeyValue element in Signature");
                }
            }
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler#cancel(
     * org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken, java.security.Principal)
     */

    /**
     * {@inheritDoc}
     */
    public RequestSecurityTokenResponse cancel(RequestSecurityToken request, Principal callerPrincipal)
            throws WSTrustException {
        // check if request contains all required elements.
        if (request.getCancelTargetElement() == null) {
            throw new WSTrustException(
                    logger.nullValueError("request does not have a cancel target. Unable to cancel token"));
        }

        // obtain the token provider that will handle the request.
        Node securityToken = request.getCancelTargetElement().getFirstChild();
        if (securityToken == null) {
            throw new WSTrustException(logger.nullValueError("security token. Unable to cancel token"));
        }

        /*
         * SecurityTokenProvider provider = this.configuration.getProviderForTokenElementNS(securityToken.getLocalName(),
         * securityToken.getNamespaceURI()); if (provider == null) throw new
         * WSTrustException("No SecurityTokenProvider configured for " + securityToken.getNamespaceURI() + ":" +
         * securityToken.getLocalName());
         */

        // create a request context and dispatch to the provider.
        WSTrustRequestContext context = new WSTrustRequestContext(request, callerPrincipal);
        // if the cancel request was made on behalf of another identity, get the principal of that identity.
        if (request.getOnBehalfOf() != null) {
            Principal onBehalfOfPrincipal = WSTrustUtil.getOnBehalfOfPrincipal(request.getOnBehalfOf());
            context.setOnBehalfOfPrincipal(onBehalfOfPrincipal);
        }
        try {
            context.setQName(new QName(securityToken.getNamespaceURI(), securityToken.getLocalName()));
            PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
            sts.initialize(configuration);
            sts.cancelToken(context);
            // provider.cancelToken(context);
        } catch (ProcessingException e) {
            throw logger.stsError(e);
        }

        // if no exception has been raised, the token has been successfully canceled.
        RequestSecurityTokenResponse response = new RequestSecurityTokenResponse();
        if (request.getContext() != null) {
            response.setContext(request.getContext());
        }
        response.setRequestedTokenCancelled(new RequestedTokenCancelledType());
        return response;
    }

    /**
     * {@inheritDoc}
     */
    public Document postProcess(Document rstrDocument, RequestSecurityToken request) throws WSTrustException {
        if (WSTrustConstants.ISSUE_REQUEST.equals(request.getRequestType().toString())
                || WSTrustConstants.RENEW_REQUEST.equals(request.getRequestType().toString())) {
            rstrDocument = DocumentUtil.normalizeNamespaces(rstrDocument);

            //extract assertion profile from subject name ID (default is VALID)
            AssertionProfile assertionProfile = AssertionProfile.VALID;
            NodeList nodeList = rstrDocument.getElementsByTagNameNS(SAML2_NS, JBossSAMLConstants.NAMEID.get());
            if (nodeList.getLength() > 0) {
                assertionProfile = AssertionProfile.getFromSubject(nodeList.item(0).getFirstChild().getNodeValue());
                if (assertionProfile == null) {
                    assertionProfile = AssertionProfile.VALID;
                }
            }

            // Sign the security token
            if (!assertionProfile.equals(AssertionProfile.UNSIGNED) && this.configuration
                    .signIssuedToken() && this.configuration.getSTSKeyPair() != null) {
                KeyPair keyPair = this.configuration.getSTSKeyPair();
                URI signatureURI = request.getSignatureAlgorithm();
                String signatureMethod = signatureURI != null ? signatureURI.toString() : SignatureMethod.RSA_SHA1;
                try {
                    Node rst = rstrDocument
                            .getElementsByTagNameNS(WSTrustConstants.BASE_NAMESPACE, "RequestedSecurityToken")
                            .item(0);
                    Element tokenElement = (Element) rst.getFirstChild();

                    logger.trace("NamespaceURI of element to be signed: " + tokenElement.getNamespaceURI());

                    //Is there a certificate?
                    X509Certificate x509Certificate = null;
                    String signingCertificateAlias = this.configuration.getSigningCertificateAlias();
                    if (signingCertificateAlias != null) {
                        x509Certificate = (X509Certificate) this.configuration.getCertificate(signingCertificateAlias);
                    }
                    // Set the CanonicalizationMethod if any
                    XMLSignatureUtil.setCanonicalizationMethodType(configuration.getXMLDSigCanonicalizationMethod());

                    rstrDocument = XMLSignatureUtil.sign(rstrDocument, tokenElement, keyPair, DigestMethod.SHA1,
                            signatureMethod, setupIDAttribute(tokenElement), x509Certificate);

                    if (logger.isTraceEnabled()) {
                        try {
                            Document tokenDocument = DocumentUtil.createDocument();
                            tokenDocument.appendChild(tokenDocument.importNode(tokenElement, true));
                            logger.trace("valid=" + XMLSignatureUtil.validate(tokenDocument, keyPair.getPublic()));

                        } catch (Exception ignore) {
                        }
                    }
                } catch (Exception e) {
                    throw new WSTrustException(logger.signatureError(e));
                }
            }

            // Other test case scenarios
            rstrDocument = postSignatureModification(rstrDocument, assertionProfile);

            // encrypt the security token if needed.
            if (this.configuration.encryptIssuedToken()) {
                // get the public key that will be used to encrypt the token.
                PublicKey providerPublicKey = null;
                if (request.getAppliesTo() != null) {
                    String serviceName = WSTrustUtil.parseAppliesTo(request.getAppliesTo());

                    logger.trace("Locating public key for " + serviceName);

                    if (serviceName != null) {
                        providerPublicKey = this.configuration.getServiceProviderPublicKey(serviceName);
                    }
                }
                if (providerPublicKey == null) {
                    logger.stsSecurityTokenShouldBeEncrypted();
                } else {
                    // generate the secret key.
                    long keySize = request.getKeySize();
                    byte[] secret = WSTrustUtil.createRandomSecret((int) keySize / 8);
                    SecretKey secretKey = new SecretKeySpec(secret, "AES");

                    // encrypt the security token.
                    Node rst = rstrDocument
                            .getElementsByTagNameNS(WSTrustConstants.BASE_NAMESPACE, "RequestedSecurityToken")
                            .item(0);
                    Element tokenElement = (Element) rst.getFirstChild();
                    try {
                        XMLEncryptionUtil.encryptElement(rstrDocument, tokenElement, providerPublicKey, secretKey,
                                (int) keySize);
                    } catch (ProcessingException e) {
                        throw new WSTrustException(logger.encryptProcessError(e));
                    }
                }
            }
        }

        return rstrDocument;
    }

    /**
     * <p>postSignatureModification.</p>
     *
     * @param rstrDocument     a {@link org.w3c.dom.Document} object.
     * @param assertionProfile a {@link net.ihe.gazelle.sts.constants.AssertionProfile} object.
     * @return a {@link org.w3c.dom.Document} object.
     */
    protected Document postSignatureModification(Document rstrDocument, AssertionProfile assertionProfile) {

        if (assertionProfile.equals(AssertionProfile.INVALID_SIGNATURE)) {
            // Corrupt signature (does not harm digests)
            NodeList signatureValueNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "SignatureValue");
            if (signatureValueNodeList.getLength() > 0) {
                Node signatureB64ValueNode = signatureValueNodeList.item(0).getFirstChild();
                byte[] signatureByteValue = Base64.decode(signatureB64ValueNode.getNodeValue());
                signatureByteValue[signatureByteValue.length - 2] = (byte) (signatureByteValue[signatureByteValue.length - 1] - (byte) 1);
                signatureB64ValueNode.setNodeValue(Base64.encodeBytes(signatureByteValue));
            }
        }

        if (assertionProfile.equals(AssertionProfile.MISSING_KEY_INFO)) {
            rstrDocument = removeNode(rstrDocument, XMLDSIG_NS, "KeyInfo");
        }

        if (assertionProfile.equals(AssertionProfile.MISSING_KEY_VALUE)) {
            rstrDocument = removeNode(rstrDocument, XMLDSIG_NS, "KeyValue");
        }

        if (assertionProfile.equals(AssertionProfile.MISSING_RSA_KEY_VALUE)) {
            rstrDocument = removeNode(rstrDocument, XMLDSIG_NS, "RSAKeyValue");
        }

        if (assertionProfile.equals(AssertionProfile.MISSING_RSA_KEY_MODULUS)) {
            rstrDocument = removeNode(rstrDocument, XMLDSIG_NS, "Modulus");
        }

        if (assertionProfile.equals(AssertionProfile.MISSING_RSA_KEY_EXPONENT)) {
            rstrDocument = removeNode(rstrDocument, XMLDSIG_NS, "Exponent");
        }
        if (assertionProfile.equals(AssertionProfile.INVALID_RSA_PUBLIC_KEY_MODULUS)) {
            NodeList modulusNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "Modulus");
            if (modulusNodeList.getLength() > 0) {
                modulusNodeList.item(0).getFirstChild().setNodeValue("testModulus");
            } else {
                logger.warn("Invalid Modulus profile: Modulus is not present in assertion !");
            }
        }
        if (assertionProfile.equals(AssertionProfile.INVALID_RSA_PUBLIC_KEY_EXPONENT)) {
            NodeList exponentNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "Exponent");
            if (exponentNodeList.getLength() > 0) {
                exponentNodeList.item(0).getFirstChild().setNodeValue("testExponent");
            } else {
                logger.warn("Invalid Exponent profile: Exponent is not present in assertion !");
            }
        }
        if (assertionProfile.equals(AssertionProfile.INVALID_X509_CERTIFICATE)) {
            NodeList x509CertificateNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "X509Certificate");
            if (x509CertificateNodeList.getLength() > 0) {
                x509CertificateNodeList.item(0).getFirstChild().setNodeValue("testX509Certificate");
            } else {
                logger.warn("Invalid X509Certificate profile: X509Certificate is not present in assertion !");
            }
        }

        if (assertionProfile.equals(AssertionProfile.NOTRUSTPROPERTY_AND_VALIDMODULUS)) {
            NodeList rsaKeyValueModulusNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "Modulus");
            if (rsaKeyValueModulusNodeList.getLength() > 0) {
                if (((GazelleSTSConfiguration) this.configuration).isIssuerTrustValidationEnabled()) {
                    logger.warn("Wrong property: Trust property is enabled !");
                }
            } else {
                logger.warn("Invalid Modulus profile: Modulus is not present in assertion !");
            }
        }

        if (assertionProfile.equals(AssertionProfile.NOTRUSTPROPERTY_AND_INVALIDMODULUS)) {
            NodeList rsaKeyValueModulusNodeList = rstrDocument.getElementsByTagNameNS(XMLDSIG_NS, "Modulus");
            if (rsaKeyValueModulusNodeList.getLength() > 0) {
                if (!((GazelleSTSConfiguration) this.configuration).isIssuerTrustValidationEnabled()) {
                    rsaKeyValueModulusNodeList.item(0).getFirstChild().setNodeValue("testModulus");
                } else {
                    logger.warn("Wrong property: Trust property is enabled !");
                }
            } else {
                logger.warn("Invalid Modulus profile: Modulus is not present in assertion !");
            }
        }

        return rstrDocument;
    }

    /**
     * <p>removeNode.</p>
     *
     * @param rstrDocument a {@link org.w3c.dom.Document} object.
     * @param namespace    a {@link java.lang.String} object.
     * @param localname    a {@link java.lang.String} object.
     * @return a {@link org.w3c.dom.Document} object.
     */
    protected Document removeNode(Document rstrDocument, String namespace, String localname) {
        NodeList nodeList = rstrDocument.getElementsByTagNameNS(namespace, localname);
        if (nodeList.getLength() > 0) {
            nodeList.item(0).getParentNode().removeChild(nodeList.item(0));
        } else {
            logger.warn("Unable to remove " + localname);
        }
        return rstrDocument;
    }

    /**
     * <p>provideAssertionProperties.</p>
     *
     * @return a {@link net.ihe.gazelle.sts.config.AssertionProperties} object.
     */
    protected AssertionProperties provideAssertionProperties() {
        return new IHEAssertionProperties();
    }

    /**
     * <p>getIssuer.</p>
     *
     * @param callerPrincipal     a {@link java.security.Principal} object.
     * @param assertionProperties a {@link net.ihe.gazelle.sts.config.AssertionProperties} object.
     * @return a {@link java.lang.String} object.
     */
    protected String getIssuer(Principal callerPrincipal, AssertionProperties assertionProperties) {
        return assertionProperties.getProperty(AssertionProperties.Keys.ISSUER);
    }

    private X509Certificate getX509CertificateFromTokenDocument(Document tokenDocument) throws ProcessingException {
        String x509CertificateString = getCertificateStringFromTokenDocument(tokenDocument);

        if (x509CertificateString == null) {
            return null;
        }
        x509CertificateString = x509CertificateString.replaceAll("[\n\r]", "");
        x509CertificateString = x509CertificateString.replaceAll(" ", "");

        return XMLSignatureUtil.getX509CertificateFromKeyInfoString(x509CertificateString);
    }

    private String getPemCertificateStringFromNode(Node securityToken) throws ConfigurationException {

        final String PEM_LINE_SEPARATOR = "\r\n";

        Document tokenDocument = DocumentUtil.createDocument();
        Node importedNode = tokenDocument.importNode(securityToken, true);
        tokenDocument.appendChild(importedNode);
        XMLSignatureUtil.propagateIDAttributeSetup(securityToken, tokenDocument.getDocumentElement());

        XMLSignatureUtil.propagateIDAttributeSetup(tokenDocument.getDocumentElement(),
                tokenDocument.getDocumentElement());

        String x509CertificateString = getCertificateStringFromTokenDocument(tokenDocument);

        if (x509CertificateString != null) {
            String intString = x509CertificateString.replaceAll(PEM_LINE_SEPARATOR, "");
            String finalString = intString.replaceAll(" ", "");

            StringBuilder builder = new StringBuilder();
            builder.append("-----BEGIN CERTIFICATE-----").append(PEM_LINE_SEPARATOR)
                    .append(finalString).append(PEM_LINE_SEPARATOR)
                    .append("-----END CERTIFICATE-----");

            return builder.toString();
        }

        return null;
    }

    private String getCertificateStringFromTokenDocument(Document tokenDocument) {
        if (tokenDocument == null) {
            throw logger.nullArgumentError("Signed Document");
        }
        NodeList signatureNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, JBossSAMLConstants.SIGNATURE.get());
        if (signatureNodeList == null || signatureNodeList.getLength() == 0) {
            throw logger.nullValueError("Cannot find Signature element");
        }
        NodeList x509CertificateNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, WSTrustConstants.XMLDSig.X509CERT);
        if (x509CertificateNodeList == null || x509CertificateNodeList.getLength() == 0) {
            return null;
        }
        return x509CertificateNodeList.item(0).getTextContent().replaceAll("\\s", "");
    }

    private RSAKeyValueType getRsaKeyValueFromTokenDocument(Document tokenDocument) {
        if (tokenDocument == null) {
            throw logger.nullArgumentError("Signed Document");
        }
        NodeList signatureNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, JBossSAMLConstants.SIGNATURE.get());
        if (signatureNodeList == null || signatureNodeList.getLength() == 0) {
            throw logger.nullValueError("Cannot find Signature element");
        }
        NodeList RsaKeyValueNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, WSTrustConstants.XMLDSig.RSA_KEYVALUE);
        if (RsaKeyValueNodeList == null || RsaKeyValueNodeList.getLength() == 0) {
            return null;
        }
        try {
            return XMLSignatureUtil.getRSAKeyValue((Element) RsaKeyValueNodeList.item(0));
        } catch (ParsingException e) {
            e.printStackTrace();
            return null;
        }

    }

    private DSAKeyValueType getDsaKeyValueFromTokenDocument(Document tokenDocument) {
        if (tokenDocument == null) {
            throw logger.nullArgumentError("Signed Document");
        }
        NodeList signatureNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, JBossSAMLConstants.SIGNATURE.get());
        if (signatureNodeList == null || signatureNodeList.getLength() == 0) {
            throw logger.nullValueError("Cannot find Signature element");
        }
        NodeList DsaKeyValueNodeList = tokenDocument
                .getElementsByTagNameNS(WSTrustConstants.XMLDSig.DSIG_NS, WSTrustConstants.XMLDSig.DSA_KEYVALUE);
        if (DsaKeyValueNodeList == null || DsaKeyValueNodeList.getLength() == 0) {
            return null;
        }
        try {
            return XMLSignatureUtil.getDSAKeyValue((Element) DsaKeyValueNodeList.item(0));
        } catch (ParsingException e) {
            e.printStackTrace();
            return null;
        }

    }

}
