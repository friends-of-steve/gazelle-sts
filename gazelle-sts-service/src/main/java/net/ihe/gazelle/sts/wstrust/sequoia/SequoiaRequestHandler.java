/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ihe.gazelle.sts.wstrust.sequoia;


import net.ihe.gazelle.sts.config.AssertionProperties;
import net.ihe.gazelle.sts.config.SequoiaAssertionProperties;
import net.ihe.gazelle.sts.dsig.KeyInfoTypeFactory;
import net.ihe.gazelle.sts.wstrust.ihe.IHERequestHandler;
import org.picketlink.common.constants.WSTrustConstants;
import org.picketlink.common.exceptions.fed.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;

import java.net.URI;
import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;

/**
 * <p>SequoiaRequestHandler class.</p>
 *
 * @author cel
 * @version $Id: $Id
 */
public class SequoiaRequestHandler extends IHERequestHandler {

    /** {@inheritDoc} */
    @Override
    protected AssertionProperties provideAssertionProperties() {
        return new SequoiaAssertionProperties();
    }

    /** {@inheritDoc} */
    @Override
    public RequestSecurityTokenResponse issue(RequestSecurityToken request, Principal callerPrincipal) throws
            WSTrustException {

        URI keyType = request.getKeyType();
        if (keyType == null) {

            //modify request content to add public key, used later into SubjectConfirmationData
            keyType = URI.create(WSTrustConstants.KEY_TYPE_PUBLIC);

            KeyPair keypair = this.configuration.getSTSKeyPair();
            KeyInfoType keyInfo = KeyInfoTypeFactory.getKeyInfoType((RSAPublicKey) keypair.getPublic());

            UseKeyType useKey = new UseKeyType();
            useKey.add(keyInfo);

            request.setKeyType(keyType);
            request.setUseKey(useKey);

        }
        return super.issue(request, callerPrincipal);
    }

}
