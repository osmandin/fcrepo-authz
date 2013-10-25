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

package org.fcrepo.auth.roles.integration;

import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.apache.http.client.ClientProtocolException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that role for unauthenticated users is properly enforced.
 * 
 * @author Scott Prater
 * @author Gregory Jansen
 */
public class BasicRolesPepUnauthenticatedUserIT extends AbstractBasicRolesIT {

    private static final Logger log = LoggerFactory
            .getLogger(BasicRolesPepUnauthenticatedUserIT.class);

    private final static String TESTDS = "uutestds";

    /* Object */
    @Test
    public void testUnauthenticatedReaderCanReadOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Unauthenticated user can read testparent1", OK
                .getStatusCode(), canRead(null, "testparent1", false));
    }

    @Test
    public void testUnauthenticatedReaderCannotWriteDatastreamOnOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot write datastream to testparent1",
                FORBIDDEN.getStatusCode(), canAddDS(null, "testparent1",
                        TESTDS, false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Unauthenticated user cannot add an ACL to testparent1",
                FORBIDDEN.getStatusCode(), canAddACL(null, "testparent1",
                        "everyone", "admin", false));
    }

    /* Object datastream (open) */
    @Test
    public void testUnauthenticatedReaderCanReadOpenObjDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user can read datastream testparent1/tsp1_data",
                OK.getStatusCode(), canRead(null, "testparent1/tsp1_data",
                        false));
    }

    @Test
    public void testUnauthenticatedReaderCannotUpdateDatastreamOnOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot update datastream testparent1/tsp1_data",
                FORBIDDEN.getStatusCode(), canUpdateDS(null, "testparent1",
                        "tsp1_data", false));
    }

    @Test
    public void testUnauthenticatedReaderCannotAddACLToOpenObjDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot add an ACL to datastream testparent1/tsp1_data",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                        "testparent1/tsp1_data", "everyone", "admin", false));
    }

    /* Object datastream (restricted) */
    @Test
    public void testUnauthenticatedReaderCannotReadRestrictedObjDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot read restricted datastream testparent1/tsp2_data",
                FORBIDDEN.getStatusCode(), canRead(null,
                        "testparent1/tsp2_data", false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotUpdateDatastreamOnRestrictedObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot update restricted datastream testparent1/tsp2_data",
                FORBIDDEN.getStatusCode(), canUpdateDS(null, "testparent1",
                        "tsp2_data", false));
    }

    @Test
    public void
    testUnauthenticatedReaderCannotAddACLToRestrictedObjDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Unauthenticated user cannot add an ACL to restricted datastream testparent1/tsp2_data",
                FORBIDDEN.getStatusCode(), canAddACL(null,
                        "testparent1/tsp2_data", "everyone", "admin", false));
    }

    /* Child object (inherits ACL) */

    /* Child object (restricted) */

    /* root node */
}
