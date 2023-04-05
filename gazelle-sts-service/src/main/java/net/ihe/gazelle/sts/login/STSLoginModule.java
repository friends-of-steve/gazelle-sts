package net.ihe.gazelle.sts.login;

import net.ihe.gazelle.sts.constants.AssertionProfile;
import net.ihe.gazelle.sts.constants.ProfileRole;
import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.UsernamePasswordLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

/**
 * Custom Login module to get credentials from {@link net.ihe.gazelle.sts.constants.AssertionProfile} enum instead of regular users.properties and
 * roles.properties.
 * <p>
 * If {@link net.ihe.gazelle.sts.constants.ProfileRole} is modified, then WEB-INF/web.xml must updated accordingly.
 * <p>
 * Created by cel on 14/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class STSLoginModule extends UsernamePasswordLoginModule {

    private static final Logger PRIVATE_LOG = LoggerFactory.getLogger(STSLoginModule.class);

    /**
     * <p>Constructor for STSLoginModule.</p>
     */
    public STSLoginModule() {
    }

    /** {@inheritDoc} */
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
                           Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
    }

    /**
     * <p>getRoleSets.</p>
     *
     * @return an array of {@link java.security.acl.Group} objects.
     * @throws javax.security.auth.login.LoginException if any.
     */
    protected Group[] getRoleSets() throws LoginException {
        String username = this.getUsername().split("\\.")[0];
        AssertionProfile assertionProfile = AssertionProfile.getFromName(username);
        if (assertionProfile != null) {
            Group rolesGroup = new SimpleGroup("Roles");
            for (ProfileRole profileRole : assertionProfile.getRoles()) {
                try {
                    Principal principalRole = createIdentity(profileRole.getRole());
                    rolesGroup.addMember(principalRole);
                } catch (Exception e) {
                    PRIVATE_LOG.warn("Unable to configure role {} for user {}: {}", profileRole.getRole(), username,
                            e.getMessage());
                }
            }
            return new Group[]{rolesGroup};
        } else {
            throw new LoginException("Invalid credentials");
        }
    }

    /**
     * <p>getUsersPassword.</p>
     *
     * @return a {@link java.lang.String} object.
     */
    protected String getUsersPassword() {
        String username = this.getUsername().split("\\.")[0];
        String password = null;
        if (username != null) {
            password = AssertionProfile.getFromName(username).getPassword();
        }

        return password;
    }

}
