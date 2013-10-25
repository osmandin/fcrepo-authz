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

package org.fcrepo.auth.xacml;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.commons.lang.NotImplementedException;
import org.fcrepo.auth.FedoraPolicyEnforcementPoint;
import org.fcrepo.auth.roles.AccessRolesProvider;
import org.fcrepo.http.commons.session.SessionFactory;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Gregory Jansen
 */
public class FedoraXacmlPEP implements FedoraPolicyEnforcementPoint {

    private static final Logger log = LoggerFactory
            .getLogger(FedoraXacmlPEP.class);

    @Autowired
    AccessRolesProvider accessRolesProvider = null;

    /**
     * @return the accessRolesProvider
     */
    public AccessRolesProvider getAccessRolesProvider() {
        return accessRolesProvider;
    }

    /**
     * @param accessRolesProvider the accessRolesProvider to set
     */
    public void setAccessRolesProvider(
            final AccessRolesProvider accessRolesProvider) {
        this.accessRolesProvider = accessRolesProvider;
    }

    @Autowired
    private SessionFactory sessionFactory = null;

    /**
     * @return the sessionFactory
     */
    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    /**
     * @param sessionFactory the sessionFactory to set
     */
    public void setSessionFactory(final SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPdp#hasModeShapePermission(org.fcrepo.auth.Path,
     * java.lang.String[], java.util.Set, java.security.Principal)
     */
    @Override
    public boolean hasModeShapePermission(final Path absPath,
            final String[] actions, final Set<Principal> allPrincipals,
            final Principal userPrincipal) {
        final boolean newNode = false;
        final Set<String> roles = new HashSet<String>();
        try {
            final Session session = sessionFactory.getInternalSession();
            final Map<String, List<String>> acl =
                    this.accessRolesProvider.findRolesForPath(absPath, session);
            for (final Principal p : allPrincipals) {
                final List<String> matchedRoles = acl.get(p.getName());
                if (roles != null) {
                    log.debug("request principal matched role assignment: " +
                            p.getName());
                    roles.addAll(matchedRoles);
                }
            }
            log.debug("roles for this request: " + roles);
        } catch (final RepositoryException e) {
            throw new Error("Cannot look up node information on " + absPath +
                    " for permissions check.", e);
        }

        if (log.isDebugEnabled()) {
            final StringBuilder msg = new StringBuilder();
            msg.append(roles.toString()).append("\t").append(
                    Arrays.toString(actions)).append("\t").append(
                    newNode ? "NEW" : "OLD").append("\t").append(
                    (absPath == null ? absPath : absPath.toString()));
            log.debug(msg.toString());
            if (actions.length > 1) { // have yet to see more than one
                log.debug("FOUND MULTIPLE ACTIONS: " +
                        Arrays.toString(actions));
            }
        }
        return false;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPolicyEnforcementPoint#filterPathsForReading(java
     * .util.Iterator, java.util.Set, java.security.Principal)
     */
    @Override
    public Iterator<Path> filterPathsForReading(final Iterator<Path> paths,
            final Set<Principal> allPrincipals, final Principal userPrincipal) {
        // TODO delegate this permission check to the PDP.
        throw new NotImplementedException();
    }

}
