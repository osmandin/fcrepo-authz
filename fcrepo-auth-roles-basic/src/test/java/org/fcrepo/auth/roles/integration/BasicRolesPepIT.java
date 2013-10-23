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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.util.EntityUtils;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that roles are properly enforced.
 *
 * @author Gregory Jansen
 */
public class BasicRolesPepIT extends AbstractBasicRolesIT {

    private static final Logger log = LoggerFactory
            .getLogger(BasicRolesPepIT.class);

    String test = "rolesTest";

    String testDS = "my_data";

    String testAdminDS = "my_admin_data";

    private static Map<String, List<String>> roles =
            new HashMap<String, List<String>>();

    private static String jsonRoles;

    static {
        roles.put("exampleadmin", Collections.singletonList("admin"));
        roles.put("examplereader", Collections.singletonList("reader"));
        roles.put("examplewriter", Collections.singletonList("writer"));
        jsonRoles = makeJson(roles);
    }

    public static String makeJson(final Map<String, List<String>> roles) {
        final ObjectMapper mapper = new ObjectMapper();
        final StringWriter sw = new StringWriter();
        try {
            mapper.writeValue(sw, roles);
            return sw.toString();
        } catch (final IOException e) {
            throw new Error(e);
        }
    }

    /**
     * Adds Basic authentication to request.
     *
     * @param method
     * @param string
     */
    private void
            setAuth(final AbstractHttpMessage method, final String username) {
        final String creds = username + ":password";
        // in test configuration we don't need real passwords
        final String encCreds =
                new String(Base64.encodeBase64(creds.getBytes()));
        final String basic = "Basic " + encCreds;
        method.setHeader("Authorization", basic);
    }

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        try {
            final HttpDelete method = deleteObjMethod(test);
            setAuth(method, "fedoraAdmin");
            client.execute(method);
        } catch (final Throwable ignored) {
        }

        {
            // post object
            final HttpPost method = postObjMethod(test);
            setAuth(method, "fedoraAdmin");
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" +
                    content, CREATED.getStatusCode(), status);
        }

        {
            // post test datastream
            final HttpPost method =
                    postDSMethod(test, testDS,
                            "This is the datastream contents.");
            setAuth(method, "fedoraAdmin");
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" +
                    content, CREATED.getStatusCode(), status);
        }

        {
            // post admin only datastream
            final HttpPost method =
                    postDSMethod(test, testAdminDS,
                            "This is the admin only datastream contents.");
            setAuth(method, "fedoraAdmin");
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" +
                    content, CREATED.getStatusCode(), status);
        }

        {
            // post test object acl
            final HttpPost method = postRolesMethod(test);
            setAuth(method, "fedoraAdmin");
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
        }

        {
            // post admin DS acl
            final HttpPost method = postRolesMethod(test + "/" + testAdminDS);
            setAuth(method, "fedoraAdmin");
            method.addHeader("Content-Type", "application/json");
            final String json =
                    makeJson(Collections.singletonMap("exampleadmin",
                            Collections.singletonList("admin")));
            final StringEntity entity = new StringEntity(json, "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
        }

        log.info("SETUP SUCCESSFUL");
    }

    private boolean canRead(final String username, final String path)
            throws IOException {
        // get the object info
        final HttpGet method = getObjectMethod(path);
        setAuth(method, username);
        final HttpResponse response = client.execute(method);
        final int status = response.getStatusLine().getStatusCode();
        return 403 != status;
    }

    private boolean canAddDS(final String username, final String path,
            final String dsName) throws IOException {
        final HttpPost method =
                postDSMethod(path, dsName, "This is the datastream contents.");
        setAuth(method, username);
        final HttpResponse response = client.execute(method);
        final int status = response.getStatusLine().getStatusCode();
        return 403 != status;
    }

    @Test
    public void testReader() throws ClientProtocolException, IOException {
        assertTrue("Reader can read " + test, canRead("examplereader", test));
        assertTrue("Reader can read " + test + "/" + testDS, canRead(
                "examplereader", test + "/" + testDS));
        assertFalse("Reader cannot read " + test + "/" + testAdminDS, canRead(
                "examplereader", test + "/" + testAdminDS));
        assertFalse("Reader cannot write", canAddDS("examplereader", test,
                "foo"));
        // assertFalse("Reader cannot write", canSetProperties("examplereader",
        // test + "/" + testAdminDS));
        // assertFalse("Reader cannot write", canSetRoles(
        // "examplereader", test + "/" + testAdminDS));
    }

    // @Test
    // public void testReaderCanReadDatastream() {
    // fail("Not yet implemented");
    // }
    //
    // @Test
    // public void testReaderCannotCreateDatastream() {
    // fail("Not yet implemented");
    // }
    //
    // @Test
    // public void testReaderCannotUpdateSparql() {
    // fail("Not yet implemented");
    // }
    //
    // @Test
    // public void testWriter() {
    // fail("Not yet implemented");
    // }

    // @Test
    // public void testAdmin() {
    // fail("Not yet implemented");
    // }

}
