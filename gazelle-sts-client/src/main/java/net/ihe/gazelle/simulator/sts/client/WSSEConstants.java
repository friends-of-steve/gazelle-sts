package net.ihe.gazelle.simulator.sts.client;

import javax.xml.namespace.QName;

/**
 * Created by aberge on 23/02/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class WSSEConstants {
    /** Constant <code>WSS_SOAP_NS="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String WSS_SOAP_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";

    /** Constant <code>WSSE_LOCAL="Security"</code> */
    public static final String WSSE_LOCAL = "Security";

    /** Constant <code>WSSE_LOCAL="Security"</code> */
    public static final String WSSE_LOCAL_PREFIXED = "wsse:Security";

    /** Constant <code>WSSE_PREFIX="wsse"</code> */
    public static final String WSSE_PREFIX = "wsse";

    /** Constant <code>WSSE_NS="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

    /** Constant <code>WSSE_BINARY_SECURITY_TOKEN="BinarySecurityToken"</code> */
    public static final String WSSE_BINARY_SECURITY_TOKEN = "BinarySecurityToken";
    /** Constant <code>WSSE_USERNAME_TOKEN="UsernameToken"</code> */
    public static final String WSSE_USERNAME_TOKEN = "UsernameToken";

    /** Constant <code>WSSE_USERNAME="Username"</code> */
    public static final String WSSE_USERNAME = "Username";
    /** Constant <code>WSSE_PASSWORD="Password"</code> */
    public static final String WSSE_PASSWORD = "Password";
    /** Constant <code>WSSE_PASSWORD_TEXT_NS="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String WSSE_PASSWORD_TEXT_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0#PasswordText";

    /** Constant <code>WSSE_ENCODING_TYPE="EncodingType"</code> */
    public static final String WSSE_ENCODING_TYPE = "EncodingType";

    /** Constant <code>WSSE_VALUE_TYPE="ValueType"</code> */
    public static final String WSSE_VALUE_TYPE = "ValueType";

    /** Constant <code>WSU_PREFIX="wsu"</code> */
    public static final String WSU_PREFIX = "wsu";

    /** Constant <code>WSU_NS="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    /** Constant <code>XML_ENCRYPTION_PREFIX="ds"</code> */
    public static final String XML_ENCRYPTION_PREFIX = "ds"; //xmlsec 1.4.2 requires this to be "ds" to correctly create KeyInfo elements

    /** Constant <code>ID="Id"</code> */
    public static final String ID = "Id";

    /** Constant <code>WSU_ID="WSU_PREFIX + : + ID"</code> */
    public static final String WSU_ID = WSU_PREFIX + ":" + ID;

    /** Constant <code>BASE64_ENCODING_TYPE="WSS_SOAP_NS + #Base64Binary"</code> */
    public static final String BASE64_ENCODING_TYPE = WSS_SOAP_NS + "#Base64Binary";

    /** Constant <code>PASSWORD_TEXT_TYPE="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String PASSWORD_TEXT_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";

    /** Constant <code>PASSWORD_DIGEST_TYPE="http://docs.oasis-open.org/wss/2004/01/"{trunked}</code> */
    public static final String PASSWORD_DIGEST_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

    /** Constant <code>WSSE_HEADER="WSSE_PREFIX + :Security"</code> */
    public static final String WSSE_HEADER = WSSE_PREFIX + ":Security";

    /** Constant <code>XMLNS_NS="http://www.w3.org/2000/xmlns/"</code> */
    public static final String XMLNS_NS = "http://www.w3.org/2000/xmlns/";

    /** Constant <code>XENC_DATAREFERENCE="DataReference"</code> */
    public static final String XENC_DATAREFERENCE = "DataReference";

    /** Constant <code>XENC_REFERENCELIST="ReferenceList"</code> */
    public static final String XENC_REFERENCELIST = "ReferenceList";


    /** Constant <code>WSSE_HEADER_QNAME</code> */
    public static final QName WSSE_HEADER_QNAME = new QName(WSSE_NS, "Security");

    /** Constant <code>WSSE_NONCE="Nonce"</code> */
    public static final String WSSE_NONCE = "Nonce";

    /** Constant <code>XMLDSIGN_NS="http://www.w3.org/2000/09/xmldsig#"</code> */
    public static final String XMLDSIGN_NS = "http://www.w3.org/2000/09/xmldsig#";

    /** Constant <code>SIGNATURE_LOCAL="Signature"</code> */
    public static final String SIGNATURE_LOCAL = "Signature";

    /** Constant <code>SAML_NS="urn:oasis:names:tc:SAML:2.0:assertion"</code> */
    public static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    /** Constant <code>ASSERTION_LOCAL="Assertion"</code> */
    public static final String ASSERTION_LOCAL = "Assertion";

    /** Constant <code>TIMESTAMP_LOCAL="Timestamp"</code> */
    public static final String TIMESTAMP_LOCAL = "Timestamp";

}
