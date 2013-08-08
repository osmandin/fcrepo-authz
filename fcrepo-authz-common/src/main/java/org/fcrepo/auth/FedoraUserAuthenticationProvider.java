/**
 * Copyright 2013 DuraSpace, Inc.
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

package org.fcrepo.auth;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.Repository;
import javax.servlet.http.HttpServletRequest;

import org.modeshape.jcr.ExecutionContext;
import org.modeshape.jcr.api.ServletCredentials;
import org.modeshape.jcr.security.AuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Gregory Jansen
 */
public class FedoraUserAuthenticationProvider implements
        AuthenticationProvider {

    /**
     * User role for Fedora's admin users
     */
    public static final String FEDORA_ADMIN = "fedoraAdmin";

    /**
     * User role for Fedora's ordinary users
     */
    public static final String FEDORA_USER = "fedoraUser";

    Logger logger = LoggerFactory
            .getLogger(FedoraUserAuthenticationProvider.class);

    Set<HTTPPrincipalFactory> principalFactories = Collections.EMPTY_SET;

    @Autowired
    private Repository repo;

    /**
     * @return the principalFactories
     */
    public Set<HTTPPrincipalFactory> getPrincipalFactories() {
        return principalFactories;
    }

    /**
     * @param principalFactories the principalFactories to set
     */
    public void setPrincipalFactories(
            final Set<HTTPPrincipalFactory> principalFactories) {
        this.principalFactories = principalFactories;
    }

    /**
     * @see org.modeshape.jcr.security.AuthenticationProvider
     *      #authenticate(javax.jcr.Credentials, java.lang.String,
     *      java.lang.String, org.modeshape.jcr.ExecutionContext, java.util.Map)
     */
    @Override
    public ExecutionContext authenticate(final Credentials credentials,
            final String repositoryName, final String workspaceName,
            final ExecutionContext repositoryContext,
            final Map<String, Object> sessionAttributes) {
        logger.debug("in authenticate: " + credentials.toString());
        if (credentials instanceof ServletCredentials) {
            // enforce fedora roles
            final ServletCredentials creds =
                    (ServletCredentials) credentials;
            logger.debug("Authenticating a request with Servlet Credentials");
            final HttpServletRequest request = creds.getRequest();
            if (request != null) {
                if (request.isUserInRole(FEDORA_USER) ||
                        request.isUserInRole(FEDORA_ADMIN)) {
                    return repositoryContext
                            .with(new FedoraUserSecurityContext(request,
                                    this.principalFactories));
                }
            }
        }
        return null;
    }

}
