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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.ItemExistsException;
import javax.jcr.ItemNotFoundException;
import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFormatException;

import org.fcrepo.auth.ServletContainerAuthenticationProvider;
import org.fcrepo.auth.roles.Constants.JcrName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Provides the effective access roles for authorization.
 *
 * @author Gregory Jansen
 */
@Component
public class AccessRolesProvider {

    private static final Logger log = LoggerFactory
            .getLogger(AccessRolesProvider.class);

    public static final Map<String, List<String>> DEFAULT_ACCESS_ROLES =
            Collections.unmodifiableMap(Collections.singletonMap(
                    ServletContainerAuthenticationProvider.EVERYONE_NAME,
                    Collections.singletonList("admin")));

    /**
     * Get the roles assigned to this Node. Optionally search up the tree for
     * the effective roles.
     *
     * @param node the subject Node
     * @param effective if true then search for effective roles
     * @return a set of roles for each principal
     */
    @SuppressWarnings("unchecked")
    public Map<String, List<String>>
    getRoles(Node node, final boolean effective) {
        final Map<String, List<String>> data =
                new HashMap<String, List<String>>();
        try {
            final Session session = node.getSession();
            Constants.registerPrefixes(session);
            if (node.isNodeType(JcrName.rbaclAssignable.getQualified())) {
                getAssignments(node, data);
                return data;
            } else {
                if (effective) { // look up the tree
                    try {
                        for (node = node.getParent(); node != null; node =
                                node.getParent()) {
                            if (node.isNodeType(JcrName.rbaclAssignable
                                    .getQualified())) {
                                getAssignments(node, data);
                                return data;
                            }
                        }
                    } catch (final ItemNotFoundException e) {
                        return DEFAULT_ACCESS_ROLES;
                    }
                }
            }
        } catch (final RepositoryException e) {
            log.error("Error gathering roles", e);
        }
        return Collections.EMPTY_MAP;
    }

    /**
     * @param node
     * @param data
     * @throws RepositoryException
     * @throws ValueFormatException
     */
    private void getAssignments(final Node node,
            final Map<String, List<String>> data) throws ValueFormatException,
            RepositoryException {
        if (node.isNodeType(JcrName.rbaclAssignable.getQualified())) {
            try {
                final Node rbacl = node.getNode(JcrName.rbacl.getQualified());
                log.debug("got rbacl: " + rbacl);
                for (final NodeIterator ni = rbacl.getNodes(); ni.hasNext();) {
                    final Node assign = ni.nextNode();
                    final String principalName =
                            assign.getProperty(JcrName.principal.getQualified())
                                    .getString();
                    List<String> roles = data.get(principalName);
                    if (roles == null) {
                        roles = new ArrayList<String>();
                        data.put(principalName, roles);
                    }
                    for (final Value v : assign.getProperty(
                            JcrName.role.getQualified()).getValues()) {
                        roles.add(v.toString());
                    }
                }
            } catch (final PathNotFoundException e) {
                log.error(
                        "Found rbaclAssignable mixin without a corresponding node.",
                        e);
            }
        }
    }

    /**
     * Assigns the given set of roles to each principal.
     *
     * @param node the Node to edit
     * @param data the roles to assign
     */
    public void postRoles(final Node node, final Map<String, Set<String>> data) {
        Session session;
        try {
            session = node.getSession();
            Constants.registerPrefixes(session);
            if (!node.isNodeType(JcrName.rbaclAssignable.getQualified())) {
                node.addMixin(JcrName.rbaclAssignable.getQualified());
                log.debug("added rbaclAssignable type");
            }

            Node acl = null;
            try {
                acl =
                        node.addNode(JcrName.rbacl.getQualified(),
                                JcrName.Rbacl.getQualified());
            } catch (final ItemExistsException e) {
                acl = node.getNode(JcrName.rbacl.getQualified());
                for (final NodeIterator ni = acl.getNodes(); ni.hasNext();) {
                    ni.nextNode().remove();
                }
            }

            for (final String key : data.keySet()) {
                final Node assign =
                        acl.addNode(JcrName.assignment.getQualified(),
                                JcrName.Assignment.getQualified());
                assign.setProperty(JcrName.principal.getQualified(), key);
                assign.setProperty(JcrName.role.getQualified(), data.get(key)
                        .toArray(new String[] {}));
            }
        } catch (final RepositoryException e1) {
            log.error("unexpected error", e1);
            throw new Error(e1);
        }
    }

    /**
     * Deletes all roles assigned on this node and removes the mixin type.
     *
     * @param node
     */
    public void deleteRoles(final Node node) {
        Session session;
        try {
            session = node.getSession();
            Constants.registerPrefixes(session);
            if (node.isNodeType(JcrName.rbaclAssignable.getQualified())) {
                // remove rbacl child
                try {
                    final Node rbacl =
                            node.getNode(JcrName.rbacl.getQualified());
                    rbacl.remove();
                } catch (final PathNotFoundException e) {
                }
                // remove mixin
                node.removeMixin(JcrName.rbaclAssignable.getQualified());
            }
        } catch (final RepositoryException e) {
            log.error("Unexpected error", e);
            throw new Error(e);
        }
    }

}
