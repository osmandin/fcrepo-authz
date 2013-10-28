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

package org.fcrepo.auth.roles;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.Node;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.fcrepo.auth.FedoraPolicyEnforcementPoint;
import org.fcrepo.http.commons.session.SessionFactory;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Gregory Jansen
 */
public class BasicRolesPEP implements FedoraPolicyEnforcementPoint {

    private static final Logger log = LoggerFactory
            .getLogger(BasicRolesPEP.class);

    private static Logger clog = LoggerFactory
            .getLogger("org.fcrepo.auth.CHECK");

    private static String AUTHZ_DETECTION = "/{" + Constants.JcrName.NS_URI +
            "}";

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
     * org.fcrepo.auth.FedoraPolicyEnforcementPoint#hasModeShapePermission(org
     * .modeshape.jcr.value.Path, java.lang.String[], java.util.Set,
     * java.security.Principal)
     */
    @Override
    public boolean hasModeShapePermission(final Path absPath,
            final String[] actions, final Set<Principal> allPrincipals,
            final Principal userPrincipal) {
        final boolean newNode = false;
        Set<String> roles = null;
        try {
            final Session session = sessionFactory.getInternalSession();
            final Node realNode = findRealNode(absPath, session);
            log.debug("using real node: " + realNode);
            roles = this.getRoles(session, allPrincipals, realNode);
            log.debug("roles for this request: " + roles);
        } catch (final RepositoryException e) {
            throw new Error("Cannot look up node information on " + absPath +
                    " for permissions check.", e);
        }

        if (clog.isDebugEnabled()) {
            final StringBuilder msg = new StringBuilder();
            msg.append(roles.toString()).append("\t").append(
                    Arrays.toString(actions)).append("\t").append(
                    newNode ? "NEW" : "OLD").append("\t").append(
                    (absPath == null ? absPath : absPath.toString()));
            clog.debug(msg.toString());
            if (actions.length > 1) { // have yet to see more than one
                clog.debug("FOUND MULTIPLE ACTIONS: " +
                        Arrays.toString(actions));
            }
        }

        if (roles.size() == 0) {
            log.debug("A caller without content roles can do nothing in the repository.");
            return false;
        }
        if (roles.contains("admin")) {
            log.debug("Granting an admin role permission to perform any action.");
            return true;
        }
        if (roles.contains("writer")) {
            if (absPath.toString().contains(AUTHZ_DETECTION)) {
                log.debug("Denying writer role permission to perform an action on an ACL node.");
                return false;
            } else {
                log.debug("Granting writer role permission to perform any action on a non-ACL nodes.");
                return true;
            }
        }
        if (roles.contains("reader")) {
            if (actions.length == 1 && "read".equals(actions[0])) {
                log.debug("Granting reader role permission to perform a read action.");
                return true;
            } else {
                log.debug("Denying reader role permission to perform a non-read action.");
                return false;
            }
        }
        log.error("There are roles in session that aren't recognized by this PEP: " +
                roles);
        return false;
    }

    /**
     * @param absPath
     * @return
     * @throws RepositoryException
     */
    private Node findRealNode(final Path absPath, final Session session)
        throws RepositoryException {
        Node result = null;
        for (Path p = absPath; p != null; p = p.getParent()) {
            try {
                if (p.isRoot()) {
                    result = session.getRootNode();
                } else {
                    result = session.getNode(p.getString());
                }
                break;
            } catch (final PathNotFoundException e) {
                log.warn("Cannot find node: " + p);
            }
        }
        return result;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPolicyEnforcementPoint#filterPathsForReading(java
     * .util.Collection, java.util.Set, java.security.Principal)
     */
    @Override
    public Iterator<Path> filterPathsForReading(final Iterator<Path> paths,
            final Set<Principal> allPrincipals, final Principal userPrincipal) {
        throw new UnsupportedOperationException();
    }

    private Set<String> getRoles(final Session session,
            final Set<Principal> principals, final Node node)
        throws RepositoryException {
        final Set<String> result = new HashSet<String>();
        final Map<String, List<String>> acl =
                this.getAccessRolesProvider().getRoles(node, true);
        for (final Principal p : principals) {
            final List<String> roles = acl.get(p.getName());
            if (roles != null) {
                log.debug("request principal matched role assignment: " +
                        p.getName());
                result.addAll(roles);
            }
        }
        return result;
    }

}
