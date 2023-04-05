package net.ihe.gazelle.simulator.sts.client;


import net.ihe.gazelle.sts.constants.AssertionProfile;
import org.apache.commons.codec.binary.Base64;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Created by aberge on 22/02/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class STSCredentials {

    /** Constant <code>BASIC="Basic "</code> */
    public static final String BASIC = "Basic ";
    private String username;
    private String password;

    /**
     * <p>Constructor for STSCredentials.</p>
     */
    public STSCredentials() {

    }

    /**
     * <p>Constructor for STSCredentials.</p>
     *
     * @param user a {@link java.lang.String} object.
     * @param pass a {@link java.lang.String} object.
     */
    public STSCredentials(String user, String pass) {
        this.username = user;
        this.password = pass;
    }

    /**
     * <p>defaultCredentials.</p>
     *
     * @return a {@link net.ihe.gazelle.simulator.sts.client.STSCredentials} object.
     */
    public static STSCredentials defaultCredentials() {
        STSCredentials credentials = new STSCredentials();
        credentials.setPassword(AssertionProfile.VALID.getPassword());
        credentials.setUsername(AssertionProfile.VALID.getName());
        return credentials;
    }

    /**
     * <p>Getter for the field <code>username</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getUsername() {
        return username;
    }

    /**
     * <p>Setter for the field <code>username</code>.</p>
     *
     * @param username a {@link java.lang.String} object.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * <p>Getter for the field <code>password</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getPassword() {
        return password;
    }

    /**
     * <p>Setter for the field <code>password</code>.</p>
     *
     * @param password a {@link java.lang.String} object.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * <p>getBasicAuthenticator.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getBasicAuthenticator() {
        StringBuilder builder = new StringBuilder(username);
        builder.append(':');
        builder.append(password);
        byte[] authenticator = builder.toString().getBytes(StandardCharsets.UTF_8);
        byte[] b64Authenticator = Base64.encodeBase64(authenticator);
        return BASIC + new String(b64Authenticator, StandardCharsets.UTF_8);
    }
}
