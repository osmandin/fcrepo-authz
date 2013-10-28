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
import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static javax.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.apache.http.client.ClientProtocolException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that role for admins is properly enforced.
 * 
 * @author Scott Prater
 * @author Gregory Jansen
 */
public class BasicRolesAdminIT extends AbstractBasicRolesIT {

    private static final Logger log = LoggerFactory
            .getLogger(BasicRolesAdminIT.class);

    private final static String TESTDS = "admintestds";

    /* Public object, one open datastream */
    @Test
    public void testAdminCanReadOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin can read testparent1", OK.getStatusCode(), canRead(
                "exampleadmin", "testparent1", true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can write datastream to testparent1", OK
                .getStatusCode(), canAddDS("exampleadmin", "testparent1",
                        TESTDS, true));
    }

    @Test
    public void testAdminCanAddACLToOpenObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin can add an ACL to testparent1", OK.getStatusCode(),
                canAddACL("exampleadmin", "testparent1",
                        "everyone", "admin", true));
    }

    /* Public object, one open datastream, one restricted datastream */
    /* object */
    @Test
    public void
    testAdminCanReadOpenObjWithRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals("Admin can read testparent2", OK.getStatusCode(), canRead(
                "exampleadmin", "testparent2", true));
    }

    /* open datastream */
    @Test
    public void testAdminCanReadOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent2/tsp1_data", OK
                .getStatusCode(), canRead("exampleadmin",
                        "testparent2/tsp1_data",
                        true));
    }

    @Test
    public void
    testAdminCanUpdateOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent2/tsp1_data",
                NO_CONTENT
                .getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent2",
                        "tsp1_data", true));
    }

    @Test
    public void testAdminCanAddACLToOpenObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent2/tsp1_data", OK
                .getStatusCode(), canAddACL("exampleadmin",
                        "testparent2/tsp1_data", "everyone", "admin", true));
    }

    /* restricted datastream */
    @Test
    public void testAdminCanReadOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read restricted datastream testparent2/tsp2_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent2/tsp2_data", true));
    }

    @Test
    public void testAdminCanUpdateOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update restricted datastream testparent2/tsp2_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent2",
                        "tsp2_data", true));
    }

    @Test
    public void testAdminCanAddACLToOpenObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to restricted datastream testparent2/tsp2_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent2/tsp2_data", "everyone", "admin", true));
    }

    /* Child object (inherits ACL), one open datastream */
    @Test
    public void testAdminCanReadInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read testparent1/testchild1NoACL", OK
                .getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild1NoACL",
                        true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can write datastream to testparent1/testchild1NoACL", OK
                .getStatusCode(), canAddDS("exampleadmin",
                        "testparent1/testchild1NoACL", TESTDS, true));
    }

    @Test
    public void testAdminCanAddACLToInheritedACLChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to testparent1/testchild1NoACL", OK
                .getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild1NoACL", "everyone", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent1/testchild1NoACL/tsc1_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild1NoACL/tsc1_data", true));
    }

    @Test
    public void testAdminCanUpdateInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent1/testchild1NoACL/tsc1_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent1/testchild1NoACL", "tsc1_data", true));
    }

    @Test
    public
    void testAdminCanAddACLToInheritedACLChildObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent1/testchild1NoACL/tsc1_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild1NoACL/tsc1_data", "everyone",
                        "admin", true));
    }

    /* Restricted child object with own ACL, two restricted datastreams */
    @Test
    public void testAdminCanReadRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read testparent1/testchild2WithACL", OK
                .getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild2WithACL", true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can write datastream to testparent1/testchild2WithACL",
                OK.getStatusCode(), canAddDS("exampleadmin",
                        "testparent1/testchild2WithACL", TESTDS, true));
    }

    @Test
    public void testAdminCanAddACLToRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to testparent1/testchild2WithACL",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild2WithACL", "everyone", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent1/testchild2WithACL/tsc1_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild2WithACL/tsc1_data", true));
    }

    @Test
    public void testAdminCanUpdateRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent1/testchild2WithACL/tsc1_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent1/testchild2WithACL", "tsc1_data", true));
    }

    @Test
    public void
    testAdminCanAddACLToRestrictedChildObjRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent1/testchild2WithACL/tsc1_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild2WithACL/tsc1_data", "everyone",
                        "admin", true));
    }

    /* Even more restricted datastream */
    @Test
    public void
    testAdminCanReadRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent1/testchild2WithACL/tsc2_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild2WithACL/tsc2_data", true));
    }

    @Test
    public
    void
    testAdminCanUpdateRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent1/testchild2WithACL/tsc2_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent1/testchild2WithACL", "tsc2_data", true));
    }

    @Test
    public
    void
    testAdminCanAddACLToRestrictedChildObjReallyRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent1/testchild2WithACL/tsc2_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild2WithACL/tsc2_data", "everyone",
                        "admin", true));
    }

    /* Writer/Admin child object with own ACL, two restricted datastreams */
    @Test
    public void testAdminCanReadWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals("Admin can read testparent1/testchild4WithACL", OK
                .getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild4WithACL", true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can write datastream to testparent1/testchild4WithACL",
                OK.getStatusCode(), canAddDS("exampleadmin",
                        "testparent1/testchild4WithACL", TESTDS, true));
    }

    @Test
    public void testAdminCanAddACLToWriterRestrictedChildObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to testparent1/testchild4WithACL",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild4WithACL", "everyone", "admin",
                        true));
    }

    @Test
    public
    void
    testAdminCanReadWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent1/testchild4WithACL/tsc1_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild4WithACL/tsc1_data", true));
    }

    @Test
    public
    void
    testAdminCanUpdateWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent1/testchild4WithACL/tsc1_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent1/testchild4WithACL", "tsc1_data", true));
    }

    @Test
    public
    void
    testAdminCanAddACLToWriterRestrictedChildObjWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent1/testchild4WithACL/tsc1_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild4WithACL/tsc1_data", "everyone",
                        "admin", true));
    }

    /* Even more restricted datastream */
    @Test
    public
    void
    testAdminCanReadWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent1/testchild4WithACL/tsc2_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent1/testchild4WithACL/tsc2_data", true));
    }

    @Test
    public
    void
    testAdminCanUpdateWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent1/testchild4WithACL/tsc2_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent1/testchild4WithACL", "tsc2_data", true));
    }

    @Test
    public
    void
    testAdminCanAddACLToWriterRestrictedChildObjReallyWriterRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent1/testchild4WithACL/tsc2_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent1/testchild4WithACL/tsc2_data", "everyone",
                        "admin", true));
    }

    /* Admin object with public datastream */
    @Test
    public void testAdminCanReadAdminObj() throws ClientProtocolException,
    IOException {
        assertEquals("Admin can read testparent2/testchild5WithACL", OK
                .getStatusCode(), canRead("exampleadmin",
                        "testparent2/testchild5WithACL", true));
    }

    @Test
    public void testAdminCanWriteDatastreamOnAdminObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can write datastream to testparent2/testchild5WithACL",
                OK.getStatusCode(), canAddDS("exampleadmin",
                        "testparent2/testchild5WithACL", TESTDS, true));
    }

    @Test
    public void testAdminCanAddACLToAdminObj()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to testparent2/testchild5WithACL",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent2/testchild5WithACL", "everyone", "admin",
                        true));
    }

    @Test
    public void testAdminCanReadAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent2/testchild5WithACL/tsc1_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent2/testchild5WithACL/tsc1_data", true));
    }

    @Test
    public void testAdminCanUpdateAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent2/testchild5WithACL/tsc1_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent2/testchild5WithACL", "tsc1_data", true));
    }

    @Test
    public void testAdminCanAddACLToAdminObjAdminRestrictedDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent2/testchild5WithACL/tsc1_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent2/testchild5WithACL/tsc1_data", "everyone",
                        "admin", true));
    }

    @Test
    public void testAdminCanReadAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can read datastream testparent2/testchild5WithACL/tsc2_data",
                OK.getStatusCode(), canRead("exampleadmin",
                        "testparent2/tsp1_data", true));
    }

    @Test
    public void testAdminCanUpdateAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can update datastream testparent2/testchild5WithACL/tsc2_data",
                NO_CONTENT.getStatusCode(), canUpdateDS("exampleadmin",
                        "testparent2/testchild5WithACL", "tsc2_data", true));
    }

    @Test
    public void testAdminCanAddACLToAdminObjPublicDatastream()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin can add an ACL to datastream testparent2/testchild5WithACL/tsc2_data",
                OK.getStatusCode(), canAddACL("exampleadmin",
                        "testparent2/testchild5WithACL/tsc2_data", "everyone",
                        "admin", true));
    }

    /* root node */
    @Test
    public void testAdminCannotReadRootNode()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot read root node", FORBIDDEN.getStatusCode(),
                canRead("exampleadmin", "/", true));
    }

    @Test
    public void testAdminCannotWriteDatastreamOnRootNode()
            throws ClientProtocolException, IOException {
        assertEquals(
                "Admin cannot write datastream to root node", FORBIDDEN
                .getStatusCode(), canAddDS("exampleadmin", "/", TESTDS, true));
    }

    @Test
    public void testAdminCannotAddACLToRootNode()
            throws ClientProtocolException, IOException {
        assertEquals("Admin cannot add an ACL to root node", FORBIDDEN
                .getStatusCode(), canAddACL("exampleadmin", "/", "everyone",
                        "admin", true));
    }
}
