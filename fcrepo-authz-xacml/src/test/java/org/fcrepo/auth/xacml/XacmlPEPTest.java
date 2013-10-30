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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.jcr.RepositoryException;

import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.http.commons.session.SessionFactory;
import org.junit.Before;
import org.junit.Test;
import org.modeshape.jcr.api.Session;


/**
 * @author Gregory Jansen
 *
 */
public class XacmlPEPTest {

    FedoraXacmlPEP pep = null;

    FedoraXacmlPDPFactory pdpFactory = null;

    AccessRolesProvider accessRolesProvider = mock(AccessRolesProvider.class);

    SessionFactory sessionFactory = mock(SessionFactory.class);

    Session session = mock(Session.class);

    Map<String, List<String>> acl = null;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        this.pdpFactory = new FedoraXacmlPDPFactory();
        this.pep = new FedoraXacmlPEP();
        this.pep.setPdpFactory(pdpFactory);
        this.pep.setAccessRolesProvider(accessRolesProvider);
        this.pep.setSessionFactory(sessionFactory);
        when(sessionFactory.getInternalSession()).thenReturn(session);
        this.acl = new HashMap<String, List<String>>();
        this.acl.put("exampleadmin", Collections.singletonList("admin"));
        this.acl.put("examplereader", Collections.singletonList("reader"));
        this.acl.put("examplewriter", Collections.singletonList("writer"));
    }

    @Test
    public void testReader() throws RepositoryException {
        final String path = "/my/data/is/here";
        // this.pep.rolesHaveModeShapePermission(RootPath.INSTANCE, new String[]
        // {"read"}, allPrincipals, userPrincipal, roles)


    }

}
