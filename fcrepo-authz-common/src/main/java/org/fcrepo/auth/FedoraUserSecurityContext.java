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

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;
import javax.servlet.http.HttpServletRequest;

import org.modeshape.jcr.security.AdvancedAuthorizationProvider;
import org.modeshape.jcr.security.SecurityContext;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Gregory Jansen
 */
public class FedoraUserSecurityContext implements SecurityContext,
        AdvancedAuthorizationProvider {

    Logger logger = LoggerFactory
            .getLogger(FedoraUserSecurityContext.class);

    private HttpServletRequest request;

    private final String username;

    private final Set<HTTPPrincipalFactory> principalFactories;

    private AuthorizationHandler authorizationHandler;

    protected FedoraUserSecurityContext(
            final HttpServletRequest request,
            final Set<HTTPPrincipalFactory> principalFactories) {
        this.request = request;
        this.principalFactories = principalFactories;
        this.username =
                request.getUserPrincipal() != null ? request
                        .getUserPrincipal().getName() : null;
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.modeshape.jcr.security.SecurityContext#isAnonymous()
     */
    @Override
    public boolean isAnonymous() {
        return false;
    }

    /**
     * {@inheritDoc SecurityContext#getUserName()}
     * 
     * @see SecurityContext#getUserName()
     */
    @Override
    public final String getUserName() {
        return username;
    }

    /**
     * {@inheritDoc SecurityContext#hasRole(String)}
     * 
     * @see SecurityContext#hasRole(String)
     */
    @Override
    public final boolean hasRole(final String roleName) {
        return request != null && request.isUserInRole(roleName);
    }

    /**
     * Get the extra principals associated with this context.
     * 
     * @return the set of principals
     */
    public Set<Principal> getGroupPrincipals() {
        final Set<Principal> result = new HashSet<Principal>();
        for (final HTTPPrincipalFactory pf : principalFactories) {
            result.addAll(pf.getGroupPrincipals(request));
        }
        return result;
    }

    /**
     * Get the user principal associated with this context.
     * 
     * @return
     */
    public Principal getUserPrincipal() {
        return this.request.getUserPrincipal();
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.modeshape.jcr.security.SecurityContext#logout()
     */
    @Override
    public void logout() {
        request = null;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.modeshape.jcr.security.AdvancedAuthorizationProvider#hasPermission
     * (org.modeshape.jcr.security.AdvancedAuthorizationProvider.Context,
     * org.modeshape.jcr.value.Path, java.lang.String[]) grabs AuthZ attributes
     * from context and delegates to a handler class subject: user roles
     * (abstract privileges?) group principals (on campus) (URIs? attrIds?) the
     * user principle resource attributes: mix-in types JCR path environment
     * attributes: ??
     */
    @Override
    public boolean hasPermission(final Context context,
            final Path absPath, final String... actions) {
        logger.debug("in hasPermission");
        // what roles do these principals have in repo (MODE-1920)
        try {
            final Privilege[] privs =
                    context.getSession().getAccessControlManager()
                            .getPrivileges(absPath.toString());
            final AccessControlPolicy[] policies =
                    context.getSession().getAccessControlManager()
                            .getEffectivePolicies(absPath.toString());
            final FedoraUserSecurityContext sContext =
                    (FedoraUserSecurityContext) context
                            .getExecutionContext().getSecurityContext();
            final Set<Principal> groupPrincipals =
                    sContext.getGroupPrincipals();
            final Principal userPrincipal = sContext.getUserPrincipal();

            // delegate to a handler
            return this.authorizationHandler.hasPermission(absPath,
                    actions, groupPrincipals, userPrincipal, privs,
                    policies);
        } catch (final RepositoryException e) {
            logger.error("Cannot check permission for ModeShape operation: " +
                    e.getLocalizedMessage());
        }
        return false;
    }
}