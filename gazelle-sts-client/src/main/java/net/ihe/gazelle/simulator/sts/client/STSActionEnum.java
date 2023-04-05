package net.ihe.gazelle.simulator.sts.client;

/**
 * Created by aberge on 27/02/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public enum STSActionEnum {
    ISSUE("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"),
    CANCEL("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"),
    RENEW("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"),
    VALIDATE("http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue");

    String soapAction;

    STSActionEnum(String value) {
        this.soapAction = value;
    }

    /**
     * <p>Getter for the field <code>soapAction</code>.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    public String getSoapAction() {
        return soapAction;
    }

    /**
     * <p>Setter for the field <code>soapAction</code>.</p>
     *
     * @param soapAction a {@link java.lang.String} object.
     */
    public void setSoapAction(String soapAction) {
        this.soapAction = soapAction;
    }
}
