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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Principal;
import java.util.Set;

import org.fcrepo.auth.roles.common.AbstractRolesPEP;
import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.core.model.context.DecisionType;
import org.jboss.security.xacml.core.model.context.EnvironmentType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Gregory Jansen
 */
public class FedoraXacmlPEP extends AbstractRolesPEP {

    private static final Logger log = LoggerFactory
            .getLogger(FedoraXacmlPEP.class);

    @Autowired
    FedoraXacmlPDPFactory pdpFactory = null;

    /**
     * @param pdpFactory the pdpFactory to set
     */
    public void setPdpFactory(final FedoraXacmlPDPFactory pdpFactory) {
        this.pdpFactory = pdpFactory;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.roles.AbstractRolesPEP#rolesHaveModeShapePermission(org
     * .modeshape.jcr.value.Path, java.lang.String[], java.util.Set)
     */
    @Override
    public boolean rolesHaveModeShapePermission(final Path absPath,
            final String[] actions, final Set<Principal> allPrincipals,
            final Principal userPrincipal, final Set<String> roles) {
        final RequestType request = new RequestType();
        request.getSubject().add(createSubject(userPrincipal.getName(), roles));
        request.getResource().add(createResource(absPath));
        request.setAction(createAction(actions));
        request.setEnvironment(new EnvironmentType());

        final RequestContext requestCtx =
                RequestResponseContextFactory.createRequestCtx();
        try {
            requestCtx.setRequest(request);
            if (log.isDebugEnabled()) {
                final ByteArrayOutputStream os = new ByteArrayOutputStream();
                try {
                    requestCtx.marshall(os);
                    final String dump = os.toString("utf-8");
                    log.debug("XACML request:\n{}", dump);
                } finally {
                    if (os != null) {
                        os.close();
                    }
                }
            }
        } catch (final IOException e) {
            throw new Error("Cannot build XACML request", e);
        }

        final ResponseContext response =
                pdpFactory.getPDP().evaluate(requestCtx);
        log.debug("PDP returned response: {}", response);
        return (DecisionType.PERMIT == response.getResult().getDecision());
    }

    /**
     * @param actions
     * @return
     */
    private ActionType createAction(final String[] actions) {
        final ActionType actionType = new ActionType();
        final AttributeType attActionID =
                RequestAttributeFactory.createMultiValuedAttributeType(
                        "urn:oasis:names:tc:xacml:1.0:action:action-id", null,
                        "http://www.w3.org/2001/XMLSchema#string", actions);
        actionType.getAttribute().add(attActionID);
        return actionType;
    }

    /**
     * @param absPath
     * @return
     */
    private ResourceType createResource(final Path absPath) {
        final ResourceType resourceType = new ResourceType();

        final AttributeType attResourceID =
                RequestAttributeFactory.createStringAttributeType(
                        "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                        null, absPath.getString());
        resourceType.getAttribute().add(attResourceID);
        return resourceType;
    }

    private SubjectType createSubject(final String userName,
            final Set<String> roles) {
        // TODO principals - typed attributes via some additional interface API

        final SubjectType subject = new SubjectType();
        subject.setSubjectCategory("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
        final AttributeType attSubjectID =
                RequestAttributeFactory.createMultiValuedAttributeType(
                        "urn:oasis:names:tc:xacml:2.0:subject:role", null,
                        "http://www.w3.org/2001/XMLSchema#string", roles
                                .toArray(new String[] {}));
        subject.getAttribute().add(attSubjectID);

        final AttributeType attUserName =
                RequestAttributeFactory.createStringAttributeType(
                        "urn:xacml:2.0:interop:example:subject:user-name",
                        null, userName);
        subject.getAttribute().add(attUserName);
        return subject;
    }

}
