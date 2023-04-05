package net.ihe.gazelle.simulator.sts.client;

import javax.xml.namespace.QName;

/**
 * Created by aberge on 03/03/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class WsTrustConstants {

    // namespaces
    /** Constant <code>POLICY_NS="http://www.w3.org/ns/ws-policy"</code> */
    public static final String POLICY_NS = "http://www.w3.org/ns/ws-policy";
    /** Constant <code>ADDRESSING_NS="http://www.w3.org/2005/08/addressing"</code> */
    public static final String ADDRESSING_NS = "http://www.w3.org/2005/08/addressing";
    /** Constant <code>WSTRUST_NS="http://docs.oasis-open.org/ws-sx/ws-tru"{trunked}</code> */
    public static final String WSTRUST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    /** Constant <code>SECEXT_NS=""</code> */
    public static final String SECEXT_NS = "";

    // prefixes
    /** Constant <code>POLICY_NS_PREFIX="wsp"</code> */
    public static final String POLICY_NS_PREFIX = "wsp";
    /** Constant <code>ADDRESSING_NS_PREFIX="wsa"</code> */
    public static final String ADDRESSING_NS_PREFIX = "wsa";
    /** Constant <code>WSTRUST_NS_PREFIX="wst"</code> */
    public static final String WSTRUST_NS_PREFIX = "wst";
    /** Constant <code>SECEXT_NS_PREFIX=""</code> */
    public static final String SECEXT_NS_PREFIX = "";

    // wst elements
    /** Constant <code>REQUEST_SECURITY_TOKEN="RequestSecurityToken"</code> */
    public static final String REQUEST_SECURITY_TOKEN = "RequestSecurityToken";
    /** Constant <code>REQUEST_SECURITY_TOKEN_NAME</code> */
    public static final QName REQUEST_SECURITY_TOKEN_NAME = new QName(WSTRUST_NS, REQUEST_SECURITY_TOKEN,
            WSTRUST_NS_PREFIX);
    /** Constant <code>REQUEST_TYPE="RequestType"</code> */
    public static final String REQUEST_TYPE = "RequestType";
    /** Constant <code>REQUEST_TYPE_NAME</code> */
    public static final QName REQUEST_TYPE_NAME = new QName(WSTRUST_NS, REQUEST_TYPE, WSTRUST_NS_PREFIX);
    /** Constant <code>TOKEN_TYPE="TokenType"</code> */
    public static final String TOKEN_TYPE = "TokenType";
    /** Constant <code>TOKEN_TYPE_NAME</code> */
    public static final QName TOKEN_TYPE_NAME = new QName(WSTRUST_NS, TOKEN_TYPE, WSTRUST_NS_PREFIX);
    /** Constant <code>VALIDATE_TARGET="ValidateTarget"</code> */
    public static final String VALIDATE_TARGET = "ValidateTarget";
    /** Constant <code>VALIDATE_TARGET_NAME</code> */
    public static final QName VALIDATE_TARGET_NAME = new QName(WSTRUST_NS, VALIDATE_TARGET, WSTRUST_NS_PREFIX);

    // wsp elements
    /** Constant <code>APPLIES_TO="AppliesTo"</code> */
    public static final String APPLIES_TO = "AppliesTo";
    /** Constant <code>APPLIES_TO_NAME</code> */
    public static final QName APPLIES_TO_NAME = new QName(POLICY_NS, APPLIES_TO, POLICY_NS_PREFIX);

    // wsa elements
    /** Constant <code>ENDPOINT_REFERENCE="EndpointReference"</code> */
    public static final String ENDPOINT_REFERENCE = "EndpointReference";
    /** Constant <code>ENDPOINT_REFERENCE_NAME</code> */
    public static final QName ENDPOINT_REFERENCE_NAME = new QName(ADDRESSING_NS, ENDPOINT_REFERENCE,
            ADDRESSING_NS_PREFIX);
    /** Constant <code>ADDRESS="Address"</code> */
    public static final String ADDRESS = "Address";
    /** Constant <code>ADDRESS_NAME</code> */
    public static final QName ADDRESS_NAME = new QName(ADDRESSING_NS, ADDRESS, ADDRESSING_NS_PREFIX);
}
