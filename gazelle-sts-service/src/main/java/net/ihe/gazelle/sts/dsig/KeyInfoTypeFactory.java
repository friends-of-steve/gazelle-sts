package net.ihe.gazelle.sts.dsig;

import org.picketlink.common.util.Base64;
import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.picketlink.identity.xmlsec.w3.xmldsig.RSAKeyValueType;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * Created by cel on 26/06/17.
 *
 * @author cel
 * @version $Id: $Id
 */
public class KeyInfoTypeFactory {

    /**
     * <p>getKeyInfoType.</p>
     *
     * @param publicKey a {@link java.security.interfaces.RSAPublicKey} object.
     * @return a {@link org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType} object.
     */
    public static KeyInfoType getKeyInfoType(RSAPublicKey publicKey) {

        RSAKeyValueType rsaKeyValueType = new RSAKeyValueType();

        rsaKeyValueType.setModulus(convertRSABigIntElementToDsigBytes(publicKey.getModulus()));
        rsaKeyValueType.setExponent(convertRSABigIntElementToDsigBytes(publicKey.getPublicExponent()));

        KeyInfoType keyInfoType = new KeyInfoType();
        keyInfoType.addContent(rsaKeyValueType);

        return keyInfoType;

    }

    private static byte[] convertRSABigIntElementToDsigBytes(BigInteger integer) {
        byte[] bigIntBytes = integer.toByteArray();
        byte[] withoutSignum = bigIntBytes[0] == 0 ? Arrays
                .copyOfRange(bigIntBytes, 1, bigIntBytes.length) : bigIntBytes;
        return Base64.encodeBytes(withoutSignum, Base64.DONT_BREAK_LINES).getBytes();
    }


}
