
package org.fcrepo.auth.roles;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.fcrepo.auth.roles.Constants.JcrName;
import org.fcrepo.auth.roles.Constants.JcrPath;
import org.fcrepo.http.commons.AbstractResource;
import org.fcrepo.http.commons.session.InjectedSession;
import org.modeshape.jcr.api.JcrTools;
import org.modeshape.jcr.api.nodetype.NodeTypeManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import com.codahale.metrics.annotation.Timed;

/**
 * RESTful interface to create and manage access roles
 *
 * @author Gregory Jansen
 * @date Sep 5, 2013
 */
@Component
@Scope("prototype")
@Path("/{path: .*}/fcr:accessRoles")
public abstract class AccessRoles extends AbstractResource {

    private static final Logger log = LoggerFactory
            .getLogger(AccessRoles.class);

    @InjectedSession
    protected Session session;

    @Context
    protected HttpServletRequest request;

    @Autowired
    private JcrTools jcrTools = new JcrTools(true);

    /**
     * @return the jcrTools
     */
    public JcrTools getJcrTools() {
        return jcrTools;
    }

    /**
     * @param jcrTools the jcrTools to set
     */
    public void setJcrTools(final JcrTools jcrTools) {
        this.jcrTools = jcrTools;
    }

    /**
     * Initialize, register role assignment node types.
     *
     * @throws RepositoryException
     * @throws IOException
     */
    @PostConstruct
    public void setUpRepositoryConfiguration() throws RepositoryException,
            IOException {
        Session session = null;
        try {
            session = sessions.getInternalSession();
            final NodeTypeManager mgr =
                    (NodeTypeManager) session.getWorkspace()
                            .getNodeTypeManager();
            mgr.registerNodeTypes(new URL("classpath:cnd/access-control.cnd"),
                    true);
            session.save();
            log.debug("Registered access role node types");
        } catch (final Exception e) {
            throw e;
        } finally {
            if (session != null) {
                session.logout();
            }
        }
    }

    @GET
    @Produces(APPLICATION_JSON)
    @Timed
    public Response get(@PathParam("path")
    final List<PathSegment> pathList) throws Exception {
        final String path = toPath(pathList);
        log.debug("Get access roles for: {}", path);
        Response.ResponseBuilder response;
        try {
            final Node node = nodeService.getObject(session, path).getNode();
            if (node.isNodeType(JcrName.rbaclAssignable.getQualifiedName())) {
                try {
                    final Node rbacl = node.getNode("rbacl");
                    final Map<String, Set<String>> data =
                            new HashMap<String, Set<String>>();
                    for (final NodeIterator ni = rbacl.getNodes(); ni.hasNext();) {
                        final Node assign = ni.nextNode();
                        final String principalName =
                                assign.getProperty(JcrPath.principal.name())
                                        .getString();
                        final Set<String> roles = new HashSet<String>();
                        for (final Value v : assign.getProperty(
                                JcrPath.role.name()).getValues()) {
                            roles.add(v.toString());
                        }
                        data.put(principalName, roles);
                    }
                    response = Response.ok(data);
                } catch (final PathNotFoundException e) {
                    response = Response.noContent();
                }
            } else {
                response = Response.noContent();
            }
        } catch (final PathNotFoundException e) {
            response = Response.status(404).entity(e.getMessage());
        } catch (final Exception e) {
            response = Response.serverError().entity(e.getMessage());
        } finally {
            session.logout();
        }
        return response.build();
    }

    @GET
    @Produces(APPLICATION_JSON)
    @Timed
    public Response get(@PathParam("path")
    final List<PathSegment> pathList, @QueryParam("effective")
    final List<String> dsidList) throws Exception {
        final String path = toPath(pathList);
        log.debug("Get effective access roles for: {}", path);
        Response.ResponseBuilder response;
        try {
            final Node node = nodeService.getObject(session, path).getNode();
            if (node.isNodeType(JcrName.rbaclAssignable.getQualifiedName())) {
                try {
                    final Node rbacl = node.getNode("rbacl");
                    final Map<String, Set<String>> data =
                            new HashMap<String, Set<String>>();
                    for (final NodeIterator ni = rbacl.getNodes(); ni.hasNext();) {
                        final Node assign = ni.nextNode();
                        final String principalName =
                                assign.getProperty(JcrPath.principal.name())
                                        .getString();
                        final Set<String> roles = new HashSet<String>();
                        for (final Value v : assign.getProperty(
                                JcrPath.role.name()).getValues()) {
                            roles.add(v.toString());
                        }
                        data.put(principalName, roles);
                    }
                    response = Response.ok(data);
                } catch (final PathNotFoundException e) {
                    response = Response.noContent();
                }
            } else {
                response = Response.noContent();
            }
        } catch (final PathNotFoundException e) {
            response = Response.status(404).entity(e.getMessage());
        } catch (final Exception e) {
            response = Response.serverError().entity(e.getMessage());
        } finally {
            session.logout();
        }
        return response.build();
    }

    @POST
    @Consumes(APPLICATION_JSON)
    @Timed
    public Response post(@PathParam("path")
    final List<PathSegment> pathList, final Map<String, Set<String>> data)
            throws Exception {
        final String path = toPath(pathList);
        log.debug("POST Received request param: {}", request);
        Response.ResponseBuilder response;

        final JcrTools jcrTools = getJcrTools();
        validatePOST(data);
        try {
            final Node node = nodeService.getObject(session, path).getNode();
            final Node rbacl =
                    jcrTools.findOrCreateNode(session, path, JcrPath.rbacl
                            .name());
            if (!rbacl.isNew()) { // clean out old assignments
                for (final NodeIterator ni = rbacl.getNodes(); ni.hasNext();) {
                    ni.nextNode().remove();
                }
            }

            for (final String key : data.keySet()) {
                final Node assign =
                        rbacl.addNode("assignment", JcrName.Assignment
                                .getQualifiedName());
                assign.setProperty(JcrPath.role.name(), data.get(key).toArray(
                        new String[] {}));
            }

            session.save();
            log.debug("Saved access roles {}", data);
            response =
                    Response.created(getUriInfo().getBaseUriBuilder()
                            .path(path).path("fcr:accessRoles").build());
        } catch (final Exception e) {
            response = Response.serverError().entity(e.getMessage());
        } finally {
            session.logout();
        }

        return response.build();
    }

    /**
     * @param data
     */
    private void validatePOST(final Map<String, Set<String>> data)
            throws IllegalArgumentException {
        if (data.isEmpty()) {
            throw new IllegalArgumentException(
                    "Posted access roles must include role assignments");
        }
        for (final String key : data.keySet()) {
            if (key == null || data.get(key) == null || data.get(key).isEmpty()) {
                throw new IllegalArgumentException(
                        "Assignments must include principal name and one or more roles");
            }
        }
    }

    /**
     * Delete the access roles and node type.
     */
    @DELETE
    @Timed
    public Response deleteNodeType(@PathParam("path")
    final List<PathSegment> pathList) throws RepositoryException {
        final String path = toPath(pathList);
        final Response.ResponseBuilder response;
        try {
            final Node node = nodeService.getObject(session, path).getNode();
            if (node.isNodeType(JcrName.rbaclAssignable.getQualifiedName())) {
                // remove rbacl child
                try {
                    final Node rbacl = node.getNode(JcrPath.rbacl.name());
                    rbacl.remove();
                } catch (final PathNotFoundException e) {

                }
                // remove mixin
                node.removeMixin(JcrName.rbaclAssignable.getQualifiedName());
                session.save();
            }
            return Response.noContent().build();
        } finally {
            session.logout();
        }
    }

    private UriInfo getUriInfo() {
        return this.uriInfo;
    }

    /**
     * Only for UNIT TESTING
     *
     * @param uriInfo
     */
    public void setUriInfo(final UriInfo uriInfo) {
        this.uriInfo = uriInfo;
    }

}
