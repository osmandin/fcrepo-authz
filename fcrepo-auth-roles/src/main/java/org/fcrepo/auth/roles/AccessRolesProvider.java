
package org.fcrepo.auth.roles;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import javax.jcr.ItemNotFoundException;
import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.fcrepo.auth.ServletContainerAuthenticationProvider;
import org.fcrepo.auth.roles.Constants.JcrName;
import org.fcrepo.kernel.services.NodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Provides the effective access roles for authorization.
 * 
 * @author Gregory Jansen
 */
@Component
public class AccessRolesProvider {

    private static final Map<String, Set<String>> DEFAULT_ACCESS_ROLES =
            Collections.singletonMap(
                    ServletContainerAuthenticationProvider.EVERYONE_NAME,
                    Collections.singleton("admin"));

    /**
     * The fcrepo node service
     */
    @Autowired
    protected NodeService nodeService;

    /**
     * Returns the effective roles for the JCR path by search up the repository
     * tree to the nearest node with the proper "rbaclAssignable" mix-in type.
     *
     * @param jcrPath the subject path
     * @param session a session
     * @return map of access roles assigned to each principal
     * @throws RepositoryException
     */
    public Map<String, Set<String>> getEffectiveRoles(final String jcrPath,
            final Session session) throws RepositoryException {
        final Node node = nodeService.getObject(session, jcrPath).getNode();
        return getEffectiveRoles(node);
    }

    /**
     * Returns the effective roles for the node by search up the repository tree
     * to the nearest node with the proper "rbaclAssignable" mix-in type.
     *
     * @param node the subject node
     * @return map of access roles assigned to each principal
     * @throws RepositoryException
     */
    public Map<String, Set<String>> getEffectiveRoles(final Node node)
            throws RepositoryException {
        if(node.isNodeType(JcrName.rbaclAssignable.name())) {
            return mapRoles(node);
        } else {
            try {
                final Node parent = node.getParent();
                return getEffectiveRoles(parent);
            } catch (final ItemNotFoundException e) {
                // this is the root node
                return DEFAULT_ACCESS_ROLES;
            }
        }
    }

    /**
     * @param node
     * @return
     */
    private Map<String, Set<String>> mapRoles(final Node node) {
        return null;
    }

}
