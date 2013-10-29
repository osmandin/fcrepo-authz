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

import static javax.ws.rs.core.Response.Status.CREATED;
import static javax.ws.rs.core.Response.Status.OK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.codehaus.jackson.map.ObjectMapper;
import org.fcrepo.auth.roles.AbstractRolesIT;
import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Gregory Jansen
 */
public class AccessRolesIT extends AbstractRolesIT {

    private static final Logger log = LoggerFactory
            .getLogger(AccessRolesIT.class);

    private static final String testobject = "testobject";

    private static Map<String, List<String>> roles =
            new HashMap<String, List<String>>();

    private static String jsonRoles;

    static {
        roles.put("exampleadmin", Collections.singletonList("admin"));
        roles.put("examplereader", Collections.singletonList("reader"));
        roles.put("examplewriter", Collections.singletonList("writer"));
        final ObjectMapper mapper = new ObjectMapper();
        final StringWriter sw = new StringWriter();
        try {
            mapper.writeValue(sw, roles);
            jsonRoles = sw.toString();
        } catch (final IOException e) {
            throw new Error(e);
        }
    }

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        try {
            final HttpDelete method = deleteObjMethod(testobject);
            client.execute(method);
        } catch (final Throwable ignored) {
        }
        {
            final HttpPost method = postObjMethod(testobject);
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" +
                    content, CREATED.getStatusCode(), status);
            final String location =
                    response.getFirstHeader("Location").getValue();
            assertEquals("Object wasn't created!", OK.getStatusCode(),
                    getStatus(new HttpGet(location)));
        }
    }

    /**
     * @throws java.lang.Exception
     */
    @After
    public void tearDown() throws Exception {
        final HttpDelete method = deleteObjMethod(testobject);
        final HttpResponse response = client.execute(method);
        final int status = response.getStatusLine().getStatusCode();
        assertEquals(204, status);
    }

    /**
     * Test method for
     * {@link org.fcrepo.auth.roles.common.AccessRoles#get(java.util.List)}.
     *
     * @throws IOException
     * @throws ClientProtocolException
     */
    @Test
    public void testGetEmptyRoles() throws ClientProtocolException, IOException {
        final HttpGet method = getRolesMethod(testobject);
        final HttpResponse response = client.execute(method);
        final HttpEntity entity = response.getEntity();
        // assertNull("There must be no content when no roles are there yet.",
        // entity);
        final int status = response.getStatusLine().getStatusCode();
        log.debug("status: " + status);
        assertEquals(204, status);
    }

    /**
     * Test method for
     * {@link org.fcrepo.auth.roles.common.AccessRoles#get(java.util.List)}.
     *
     * @throws IOException
     * @throws ClientProtocolException
     */
    @Test
    public void testCRUDRoles() throws ClientProtocolException, IOException {
        { // first post some roles
            final HttpPost method = postRolesMethod(testobject);
            method.addHeader("Content-Type", "application/json");
            final StringEntity entity = new StringEntity(jsonRoles, "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertNotNull("There must be content for a post.", response
                    .getEntity());
            final String content = EntityUtils.toString(response.getEntity());
            log.debug("post response content: \n" + content);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
            final String location =
                    response.getFirstHeader("Location").getValue();
            assertEquals("Got wrong Location header for roles node!",
                    serverAddress + testobject + "/" + SUFFIX, location);
        }

        { // Get the roles
            final HttpGet method = getRolesMethod(testobject);
            final HttpResponse response = client.execute(method);
            final int status = response.getStatusLine().getStatusCode();
            log.debug("status: " + status);
            assertEquals(200, status);

            final HttpEntity entity = response.getEntity();
            assertNotNull("There must be content when roles present.", entity);
            final String content = EntityUtils.toString(entity);
            log.debug("content: " + content);
            final ObjectMapper mapper = new ObjectMapper();
            final Map result = mapper.readValue(content, Map.class);
            assertEquals("result must equal test data", roles, result);
        }

        { // delete the roles
            final HttpDelete method = deleteRolesMethod(testobject);
            final HttpResponse response = client.execute(method);
            final int status = response.getStatusLine().getStatusCode();
            log.debug("status: " + status);
            assertEquals(204, status);
        }

        { // verify that roles are gone
            final HttpGet method = getRolesMethod(testobject);
            final HttpResponse response = client.execute(method);
            final HttpEntity entity = response.getEntity();
            final int status = response.getStatusLine().getStatusCode();
            log.debug("status: " + status);
            assertEquals(204, status);
        }
    }

    /**
     * Test method for
     * {@link org.fcrepo.auth.roles.common.AccessRoles#get(java.util.List, java.util.List)}
     * .
     *
     * @throws IOException
     * @throws ClientProtocolException
     */
    @Test
    public void testGetEffectiveRoles() throws ClientProtocolException,
            IOException {
        { // verify that default roles are returned
            final HttpGet method = getEffectiveRolesMethod(testobject);
            final HttpResponse response = client.execute(method);
            final int status = response.getStatusLine().getStatusCode();
            log.debug("effective status: " + status);
            assertEquals(200, status);

            final HttpEntity entity = response.getEntity();
            assertNotNull("There must be content when roles present.", entity);
            final String content = EntityUtils.toString(entity);
            log.debug("content: " + content);
            final ObjectMapper mapper = new ObjectMapper();
            final Map result = mapper.readValue(content, Map.class);
            assertEquals("result must equal test data",
                    AccessRolesProvider.DEFAULT_ACCESS_ROLES, result);
        }

        { // create a child
            final HttpPost method = postObjMethod(testobject + "/testchild");
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" +
                    content, CREATED.getStatusCode(), status);
            final String location =
                    response.getFirstHeader("Location").getValue();
            assertEquals("Object wasn't created!", OK.getStatusCode(),
                    getStatus(new HttpGet(location)));
        }

        { // post some roles on parent
            final HttpPost method = postRolesMethod(testobject);
            method.addHeader("Content-Type", "application/json");
            final StringEntity entity = new StringEntity(jsonRoles, "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertNotNull("There must be content for a post.", response
                    .getEntity());
            final String content = EntityUtils.toString(response.getEntity());
            log.debug("post response content: \n" + content);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
            final String location =
                    response.getFirstHeader("Location").getValue();
            assertEquals("Got wrong Location header for roles node!",
                    serverAddress + testobject + "/" + SUFFIX, location);
        }

        { // see that parent roles are effective for child
            final HttpGet method =
                    getEffectiveRolesMethod(testobject + "/testchild");
            final HttpResponse response = client.execute(method);
            final int status = response.getStatusLine().getStatusCode();
            log.debug("status: " + status);
            assertEquals(200, status);

            final HttpEntity entity = response.getEntity();
            assertNotNull("There must be content when roles present.", entity);
            final String content = EntityUtils.toString(entity);
            log.debug("content: " + content);
            final ObjectMapper mapper = new ObjectMapper();
            final Map result = mapper.readValue(content, Map.class);
            assertEquals("result must equal test data", roles, result);
        }

        final Map<String, List<String>> childRoles =
                Collections.singletonMap("exampleadmin", Collections
                        .singletonList("admin"));

        { // post different acl with fewer roles on the child
            final ObjectMapper mapper = new ObjectMapper();
            final StringWriter sw = new StringWriter();
            try {
                mapper.writeValue(sw, childRoles);
            } catch (final IOException e) {
                throw new Error(e);
            }

            final HttpPost method = postRolesMethod(testobject + "/testchild");
            method.addHeader("Content-Type", "application/json");
            final StringEntity entity =
                    new StringEntity(sw.toString(), "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertNotNull("There must be content for a post.", response
                    .getEntity());
            final String content = EntityUtils.toString(response.getEntity());
            log.debug("post response content: \n" + content);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
            final String location =
                    response.getFirstHeader("Location").getValue();
            assertEquals("Got wrong Location header for roles node!",
                    serverAddress + testobject + "/testchild" + "/" + SUFFIX,
                    location);
        }

        { // see that only child roles are effective for child
            final HttpGet method =
                    getEffectiveRolesMethod(testobject + "/testchild");
            final HttpResponse response = client.execute(method);
            final int status = response.getStatusLine().getStatusCode();
            log.debug("status: " + status);
            assertEquals(200, status);

            final HttpEntity entity = response.getEntity();
            assertNotNull("There must be content when roles present.", entity);
            final String content = EntityUtils.toString(entity);
            log.debug("content: " + content);
            final ObjectMapper mapper = new ObjectMapper();
            final Map result = mapper.readValue(content, Map.class);
            assertEquals("result must equal test data", childRoles, result);
        }
    }

}
