package net.ihe.gazelle.sts.constants;

import org.junit.Test;

/**
 * Created by cel on 14/06/17.
 */
public class IHEAssertionProfileTest {

    @Test
    public void getFromNameTest() {
        AssertionProfile profile = AssertionProfile.getFromName("valid");
        assert profile.equals(AssertionProfile.VALID);
    }

    @Test
    public void getFromNameErrorTest() {
        AssertionProfile profile = AssertionProfile.getFromName("doesnotexistinenum");
        assert profile == null;
    }

}
