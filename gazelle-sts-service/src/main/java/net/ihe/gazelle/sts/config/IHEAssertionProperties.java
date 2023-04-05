package net.ihe.gazelle.sts.config;

import java.io.File;

/**
 * Created by cel on 07/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class IHEAssertionProperties extends AssertionProperties {

    IHEAssertionProperties(String rootPath) {
        super(rootPath);
    }

    public IHEAssertionProperties() {
        super();
    }

    /**
     * <p>getPropertyFilePath.</p>
     *
     * @param root a {@link java.lang.String} object.
     * @return a {@link java.lang.String} object.
     */
    protected String getPropertyFilePath(String root) {
        return root + File.separator + "ihe.assertion.properties";
    }



}