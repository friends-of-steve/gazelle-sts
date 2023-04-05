package net.ihe.gazelle.sts.config;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.fail;

public class AssertionPropertiesTest {

    private AssertionProperties assertionProperties;
    private String tempDirectoryPath;

    @Before
    public void setUp() throws IOException {
        Path tempDirectory = Files.createTempDirectory("sts");
        tempDirectoryPath = tempDirectory.toAbsolutePath().toString();
    }

    @Test
    public void testGetDomainPropertyFromPropertiesFileIHE() throws IOException {
        InputStream inputStream = AssertionPropertiesTest.class.getResourceAsStream("/ihe.assertion.properties");
        Files.copy(inputStream, Paths.get(tempDirectoryPath + "/ihe.assertion.properties"));
        assertionProperties = new IHEAssertionProperties(tempDirectoryPath);

        String properties = assertionProperties.getProperty(AssertionProperties.Keys.DOMAIN);
        Assert.assertEquals("ihe-europe.net", properties);
    }

    @Test
    public void testGetDomainPropertyFromPropertiesFileIHEMissingKey() throws IOException {
        InputStream inputStream = AssertionPropertiesTest.class.getResourceAsStream("/test.ihe.properties");
        Files.copy(inputStream, Paths.get(tempDirectoryPath + "/ihe.assertion.properties"));
        assertionProperties = new IHEAssertionProperties(tempDirectoryPath);

        try {
            assertionProperties.getProperty(AssertionProperties.Keys.DOMAIN);
        } catch (MissingPropertyException e){
            return;
        }
        fail("A MissingPropertyException should be thrown !");
    }

    @Test
    public void testGetDomainPropertyFromPropertiesFileIHEMissingFile() {
        assertionProperties = new IHEAssertionProperties(tempDirectoryPath);

        try {
            assertionProperties.getProperty(AssertionProperties.Keys.DOMAIN);
        } catch (MissingPropertyFileException e){
            return;
        }
        fail("A MissingPropertyFileException should be thrown !");
    }

    @Test
    public void testGetIssuerPropertyFromPropertiesFileSequoia() throws IOException {
        InputStream inputStream = AssertionPropertiesTest.class.getResourceAsStream("/sequoia.assertion.properties");
        Files.copy(inputStream, Paths.get(tempDirectoryPath + "/sequoia.assertion.properties"));
        assertionProperties = new SequoiaAssertionProperties(tempDirectoryPath);

        String properties = assertionProperties.getProperty(AssertionProperties.Keys.ISSUER);
        Assert.assertEquals("CN=validation.sequoiaproject.org, OU=NHIN-Test, O=NHIN, C=US", properties);
    }

    @Test
    public void testGetIssuerPropertyFromPropertiesFileSequoiaMissingKey() throws IOException {
        InputStream inputStream = AssertionPropertiesTest.class.getResourceAsStream("/test.sequoia.properties");
        Files.copy(inputStream, Paths.get(tempDirectoryPath + "/sequoia.assertion.properties"));
        assertionProperties = new SequoiaAssertionProperties(tempDirectoryPath);

        try {
            assertionProperties.getProperty(AssertionProperties.Keys.ISSUER);
        } catch (MissingPropertyException e){
            return;
        }
        fail("A MissingPropertyException shall be raised !");
    }

    @Test
    public void testGetIssuerPropertyFromPropertiesFileSequoiaMissingFile() {
        assertionProperties = new SequoiaAssertionProperties(tempDirectoryPath);

        try {
            assertionProperties.getProperty(AssertionProperties.Keys.ISSUER);
        } catch (MissingPropertyFileException e){
            return;
        }
        fail("A MissingPropertyFileException shall be raised !");
    }
}