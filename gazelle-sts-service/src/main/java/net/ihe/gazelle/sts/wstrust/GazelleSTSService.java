package net.ihe.gazelle.sts.wstrust;
/*
 * JBoss, Home of Professional Open Source. Copyright 2009, Red Hat Middleware LLC, and individual contributors as
 * indicated by the @author tags. See the copyright.txt file in the distribution for a full listing of individual
 * contributors.
 * 
 * This is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with this software; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF site:
 * http://www.fsf.org.
 */

import net.ihe.gazelle.sts.config.GazelleSTSConfigParser;
import net.ihe.gazelle.sts.config.GazelleSTSConfiguration;
import net.ihe.gazelle.sts.config.GazelleSTSType;
import net.ihe.gazelle.sts.parsers.IHEWSTrustParser;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.picketlink.common.ErrorCodes;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.fed.WSTrustException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.SOAPUtil;
import org.picketlink.identity.federation.core.wstrust.PicketLinkSTS;
import org.picketlink.identity.federation.core.wstrust.PicketLinkSTSConfiguration;
import org.picketlink.identity.federation.core.wstrust.STSConfiguration;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestHandler;
import org.picketlink.identity.federation.core.wstrust.wrappers.BaseRequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenCollection;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.annotation.Resource;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.WebServiceProvider;
import javax.xml.ws.soap.Addressing;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * <p>
 * Gazelle implementation of the {@code SecurityTokenService} interface.
 * </p>
 *
 * @author cel@kereval.com
 * @version $Id: $Id
 */
@WebServiceProvider(serviceName = "GazelleSTS", portName = "GazelleSTSPort", targetNamespace = "urn:gazelle.ihe.net:sts", wsdlLocation = "wsdl/GazelleSTS.wsdl")
@ServiceMode(value = Service.Mode.MESSAGE)
@Addressing(enabled = true, required = false)
public class GazelleSTSService extends PicketLinkSTS {

    private static final String SEPARATOR = AccessController.doPrivileged(new PrivilegedAction<String>() {
        public String run() {
            return System.getProperty("file.separator");
        }
    });
    private static final String STS_CONFIG_FILE = "picketlink-sts.xml";
    public static final String STS_CONFIG_DIR = SEPARATOR + "opt" + SEPARATOR + "sts";

    private static final Logger LOG = Logger.getLogger(GazelleSTSService.class);

    /**
     * <p>setWSC.</p>
     *
     * @param wctx a {@link javax.xml.ws.WebServiceContext} object.
     */
    @Resource
    public void setWSC(WebServiceContext wctx) {
        LOG.debug("Setting WebServiceContext = " + wctx);
        this.context = wctx;
    }

    /** {@inheritDoc} */
    @Override
    public SOAPMessage invoke(SOAPMessage request) {
        String valueType = null;
        Node binaryToken = null;
        boolean soap12 = false;

        // Check headers
        try {
            soap12 = SOAPUtil.isSOAP12(request);
            SOAPHeader soapHeader = request.getSOAPHeader();
            binaryToken = getBinaryToken(soapHeader);
            if (binaryToken != null) {
                NamedNodeMap namedNodeMap = binaryToken.getAttributes();
                int length = namedNodeMap != null ? namedNodeMap.getLength() : 0;
                for (int i = 0; i < length; i++) {
                    Node nodeValueType = namedNodeMap.getNamedItem(WSTrustConstants.WSSE.VALUE_TYPE);
                    if (nodeValueType != null) {
                        valueType = nodeValueType.getNodeValue();
                        break;
                    }
                }
            }
        } catch (SOAPException e) {
            throw new WebServiceException("Security Token Service Exception", e);
        }
        Node payLoad;
        BaseRequestSecurityToken baseRequest;
        try {
            payLoad = SOAPUtil.getSOAPData(request);

            IHEWSTrustParser parser = new IHEWSTrustParser();

            baseRequest = (BaseRequestSecurityToken) parser.parse(DocumentUtil.getNodeAsStream(payLoad));
        } catch (Exception e) {
            throw new WebServiceException("Security Token Service Exception", e);
        }

        if (baseRequest instanceof RequestSecurityToken) {
            RequestSecurityToken req = (RequestSecurityToken) baseRequest;
            try {
                req.setRSTDocument((Document) payLoad);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            if (binaryToken != null) {
                req.setBinaryToken(binaryToken);
            }

            if (valueType != null) {
                req.setBinaryValueType(URI.create(valueType));
            }
            Source theResponse = this.handleTokenRequest(req);
            return convert(theResponse, soap12);
        } else if (baseRequest instanceof RequestSecurityTokenCollection) {
            return convert(this.handleTokenRequestCollection((RequestSecurityTokenCollection) baseRequest), soap12);
        } else {
            throw new WebServiceException(ErrorCodes.STS_INVALID_TOKEN_REQUEST);
        }
    }


    /** {@inheritDoc} */
    @Override
    protected STSConfiguration getConfiguration() throws ConfigurationException {
        URL configurationFileURL = null;
        InputStream stream = null;

        try {
            // check the user home for a configuration file generated by the picketlink console.
            String configurationFilePath = STS_CONFIG_DIR + SEPARATOR + STS_CONFIG_FILE;
            File configurationFile = new File(configurationFilePath);
            if (configurationFile.exists()) {
                configurationFileURL = configurationFile.toURI().toURL();
            } else {
                configurationFileURL = SecurityActions.loadResource(getClass(), STS_CONFIG_FILE);

                // fallback to the old configuration
                if (configurationFileURL == null) {
                    configurationFileURL = SecurityActions.loadResource(getClass(), STS_CONFIG_FILE);
                }
            }

            // if no configuration file was found, log a warn message and use default configuration values.
            if (configurationFileURL == null) {
                LOG.warn("Configuration file not found using URL. Using default configuration values");
                return new PicketLinkSTSConfiguration();
            }

            stream = configurationFileURL.openStream();
            GazelleSTSType stsConfig = (GazelleSTSType) new GazelleSTSConfigParser().parse(stream);
            STSConfiguration configuration = new GazelleSTSConfiguration(stsConfig);
            if (LOG.isInfoEnabled()) {
                LOG.info(STS_CONFIG_FILE + " configuration file loaded");
            }
            return configuration;
        } catch (Exception e) {
            throw new ConfigurationException(ErrorCodes.STS_CONFIGURATION_FILE_PARSING_ERROR, e);
        } finally {
            IOUtils.closeQuietly(stream);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Process a security token request.
     * </p>
     */
    @Override
    protected Source handleTokenRequest(RequestSecurityToken request) {
        if (context == null) {
            throw new IllegalStateException(ErrorCodes.NULL_VALUE + "WebServiceContext");
        }
        if (this.config == null) {
            try {
                LOG.info("Loading STS configuration");
                this.config = this.getConfiguration();
            } catch (ConfigurationException e) {
                throw new WebServiceException(e);
            }
        }

        WSTrustRequestHandler handler = this.config.getRequestHandler();
        if (handler == null) {
            throw new WebServiceException("WSTrustRequestHandler not defined");
        }

        String requestType = request.getRequestType().toString();

        LOG.trace("STS received request of type " + requestType);

        try {
            if (requestType.equals(WSTrustConstants.ISSUE_REQUEST)) {
                Source source = this.marshallResponse(handler.issue(request, this.context.getUserPrincipal()));
                Document doc = handler.postProcess((Document) ((DOMSource) source).getNode(), request);
                return new DOMSource(doc);
            } else if (requestType.equals(WSTrustConstants.RENEW_REQUEST)) {
                Source source = this.marshallResponse(handler.renew(request, this.context.getUserPrincipal()));
                // we need to sign/encrypt renewed tokens.
                Document document = handler.postProcess((Document) ((DOMSource) source).getNode(), request);
                return new DOMSource(document);
            } else if (requestType.equals(WSTrustConstants.CANCEL_REQUEST)) {
                return this.marshallResponse(handler.cancel(request, this.context.getUserPrincipal()));
            } else if (requestType.equals(WSTrustConstants.VALIDATE_REQUEST)) {
                return this.marshallResponse(handler.validate(request, this.context.getUserPrincipal()));
            } else {
                throw new WebServiceException("Invalid Request Type: " + requestType);
            }
        } catch (WSTrustException we) {
            throw new WebServiceException("Error while handling token Request: " + we.getMessage());
        }
    }

    private SOAPMessage convert(Source theResponse, boolean wantSOAP12) {
        try {
            SOAPMessage response = null;

            if (wantSOAP12) {
                response = SOAPUtil.createSOAP12();
            } else {
                response = SOAPUtil.create();
            }
            Document theResponseDoc = (Document) DocumentUtil.getNodeFromSource(theResponse);
            response.getSOAPBody().addDocument(theResponseDoc);
            return response;
        } catch (Exception e) {
            throw new WebServiceException("Security Token Service Exception", e);
        }
    }

    private Node getBinaryToken(SOAPHeader soapHeader) {
        if (soapHeader != null) {
            NodeList children = soapHeader.getChildNodes();
            int length = children != null ? children.getLength() : 0;
            for (int i = 0; i < length; i++) {
                Node child = children.item(i);
                if (child.getNodeName().contains(WSTrustConstants.WSSE.BINARY_SECURITY_TOKEN)) {
                    return child;
                }
            }
        }
        return null;
    }

}
