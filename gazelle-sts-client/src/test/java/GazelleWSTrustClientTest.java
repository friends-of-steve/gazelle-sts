import net.ihe.gazelle.simulator.sts.client.GazelleWSTtrustClient;
import net.ihe.gazelle.sts.constants.AssertionProfile;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * Created by cel on 14/06/17.
 */
public class GazelleWSTrustClientTest {

    private static final Logger LOG = LoggerFactory.getLogger(GazelleWSTrustClientTest.class);
    private static final String ENDPOINT = "http://localhost:8180/gazelle-sts?wsdl";

    @Before
    public void setUp() {
        Assume.assumeTrue(isServiceReachable());
    }

    @Test
    public void issueAssertionTest() {
        GazelleWSTtrustClient gazelleWSTtrustClient = new GazelleWSTtrustClient(ENDPOINT);
        try {
            Element assertion = gazelleWSTtrustClient.issueAssertion(AssertionProfile.VALID, "https://gazelle.ihe.net");
            LOG.info("Issued assertion:\n{}", assertion.toString());
            assert true;
        } catch (Exception e) {
            LOG.error("Error while requesting assertion:\n{}", e.getMessage());
            assert false;
        }
    }

    private boolean isServiceReachable() {
        HttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(ENDPOINT);
        try {
            HttpResponse response = httpClient.execute(httpGet);
            if (response.getStatusLine().getStatusCode() != 200) {
                return false;
            } else {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

}
