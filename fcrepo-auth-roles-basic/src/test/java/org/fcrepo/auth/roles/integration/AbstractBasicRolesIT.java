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
import static org.junit.Assert.assertNotNull;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.util.EntityUtils;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/spring-test/test-container.xml")
public abstract class AbstractBasicRolesIT {

    private static Logger logger = getLogger(AbstractBasicRolesIT.class);

    protected static final int SERVER_PORT = Integer.parseInt(System
            .getProperty("test.port", "8080"));

    protected static final String HOSTNAME = "localhost";

    protected static final String SUFFIX = "fcr:accessRoles";

    protected static final String serverAddress = "http://" + HOSTNAME + ":" +
            SERVER_PORT + "/rest/";

    protected final PoolingClientConnectionManager connectionManager =
            new PoolingClientConnectionManager();

    protected static HttpClient client;

    private final static List<BasicRolesPepTestObjectBean> test_objs =
            defineTestObjects();

    public AbstractBasicRolesIT() {
        connectionManager.setMaxTotal(Integer.MAX_VALUE);
        connectionManager.setDefaultMaxPerRoute(20);
        connectionManager.closeIdleConnections(3, TimeUnit.SECONDS);
        client = new DefaultHttpClient(connectionManager);
    }

    @Before
    public void setUp() throws Exception {
        for (final BasicRolesPepTestObjectBean obj : test_objs) {

            deleteTestObject(obj);
            ingestObject(obj);

        }
        logger.info("SETUP SUCCESSFUL");
    }

    protected HttpGet getRolesMethod(final String param) {
        final HttpGet get = new HttpGet(serverAddress + param + "/" + SUFFIX);
        logger.debug("GET: {}", get.getURI());
        return get;
    }

    protected HttpGet getEffectiveRolesMethod(final String param) {
        final HttpGet get =
                new HttpGet(serverAddress + param + "/" + SUFFIX + "?effective");
        logger.debug("GET: {}", get.getURI());
        return get;
    }

    protected HttpGet getObjectMethod(final String param) {
        final HttpGet get = new HttpGet(serverAddress + param);
        logger.debug("GET: {}", get.getURI());
        return get;
    }

    protected HttpPost postObjMethod(final String param) {
        final HttpPost post = new HttpPost(serverAddress + param);
        logger.debug("POST: {}", post.getURI());
        return post;
    }

    protected static HttpPost postDSMethod(final String objectPath,
            final String ds, final String content)
                    throws UnsupportedEncodingException {
        final HttpPost post =
                new HttpPost(serverAddress + objectPath + "/" + ds +
                        "/fcr:content");
        post.setEntity(new StringEntity(content));
        return post;
    }

    protected HttpPost postRolesMethod(final String param) {
        final HttpPost post =
                new HttpPost(serverAddress + param + "/" + SUFFIX);
        logger.debug("POST: {}", post.getURI());
        return post;
    }

    protected HttpDelete deleteObjMethod(final String param) {
        final HttpDelete delete = new HttpDelete(serverAddress + param);
        logger.debug("DELETE: {}", delete.getURI());
        return delete;
    }

    protected HttpDelete deleteRolesMethod(final String param) {
        final HttpDelete delete = new HttpDelete(serverAddress + param + "/" + SUFFIX);
        logger.debug("DELETE: {}", delete.getURI());
        return delete;
    }

    protected HttpResponse execute(final HttpUriRequest method)
            throws IOException {
        logger.debug("Executing: " + method.getMethod() + " to " +
                method.getURI());
        return client.execute(method);
    }

    protected int getStatus(final HttpUriRequest method)
            throws IOException {
        final HttpResponse response = execute(method);
        final int result = response.getStatusLine().getStatusCode();
        if (!(result > 199) || !(result < 400)) {
            logger.warn(EntityUtils.toString(response.getEntity()));
        }
        return result;
    }

    protected boolean canRead(final String username, final String path,
            final boolean is_authenticated)
            throws IOException {
        // get the object info
        final HttpGet method = getObjectMethod(path);
        if (is_authenticated) {
            setAuth(method, username);
        }
        final HttpResponse response = client.execute(method);
        final int status = response.getStatusLine().getStatusCode();
        return 403 != status;
    }

    protected boolean canAddDS(final String username, final String path,
            final String dsName, final boolean is_authenticated)
            throws IOException {
        final HttpPost method =
                postDSMethod(path, dsName, "This is the datastream contents.");
        if (is_authenticated) {
            setAuth(method, username);
        }
        final HttpResponse response = client.execute(method);
        final int status = response.getStatusLine().getStatusCode();
        return 403 != status;
    }

    private void
    setAuth(final AbstractHttpMessage method,
            final String username) {
        final String creds = username + ":password";
        // in test configuration we don't need real passwords
        final String encCreds =
                new String(Base64.encodeBase64(creds.getBytes()));
        final String basic = "Basic " + encCreds;
        method.setHeader("Authorization", basic);
    }

    private void deleteTestObject(final BasicRolesPepTestObjectBean obj) {
        try {
            final HttpDelete method = deleteObjMethod(obj.getPath());
            setAuth(method, "fedoraAdmin");
            client.execute(method);
        } catch (final Throwable ignored) {
            logger.debug("object {} doesn't exist -- not deleting", obj
                    .getPath());

        }
    }

    private void ingestObject(final BasicRolesPepTestObjectBean obj)
            throws Exception {
        final HttpPost method = postObjMethod(obj.getPath());
        setAuth(method, "fedoraAdmin");
        final HttpResponse response = client.execute(method);
        final String content = EntityUtils.toString(response.getEntity());
        final int status = response.getStatusLine().getStatusCode();
        assertEquals("Didn't get a CREATED response! Got content:\n" + content,
                CREATED.getStatusCode(), status);

        addObjectACLs(obj);
        addDatastreams(obj);
    }

    private void addObjectACLs(final BasicRolesPepTestObjectBean obj)
            throws Exception {
        if (obj.getACLs().size() > 0) {
            final String jsonACLs = createJsonACLs(obj.getACLs());

            final HttpPost method = postRolesMethod(obj.getPath());
            setAuth(method, "fedoraAdmin");
            method.addHeader("Content-Type", "application/json");
            final StringEntity entity = new StringEntity(jsonACLs, "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertNotNull("There must be content for a post.", response.getEntity());
            final String content = EntityUtils.toString(response.getEntity());
            logger.debug("post response content: \n {}", content);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
        }
    }

    private void addDatastreams(final BasicRolesPepTestObjectBean obj)
            throws Exception {
        for (final Map<String, String> entries : obj.getDatastreams()) {
            for (final Map.Entry<String, String> entry : entries.entrySet()) {
                final String dsid = entry.getKey();
                final HttpPost method =
                        postDSMethod(obj.getPath(), dsid, entry.getValue());
                setAuth(method, "fedoraAdmin");
                final HttpResponse response = client.execute(method);
                final String content =
                        EntityUtils.toString(response.getEntity());
                final int status = response.getStatusLine().getStatusCode();
                assertEquals("Didn't get a CREATED response! Got content:\n" +
                        content, CREATED.getStatusCode(), status);
                addDatastreamACLs(obj, dsid);
            }
        }
    }

    private void addDatastreamACLs(final BasicRolesPepTestObjectBean obj,
            final String dsid) throws Exception {
        if (obj.getDatastreamACLs(dsid) != null) {
            final List<Map<String, String>> dsACLs =
                    Collections.singletonList(obj.getDatastreamACLs(dsid));
            final String jsonACLs = createJsonACLs(dsACLs);
            final HttpPost method = postRolesMethod(obj.getPath() + "/" + dsid);
            setAuth(method, "fedoraAdmin");
            method.addHeader("Content-Type", "application/json");
            final StringEntity entity = new StringEntity(jsonACLs, "utf-8");
            method.setEntity(entity);
            final HttpResponse response = client.execute(method);
            assertEquals(CREATED.getStatusCode(), response.getStatusLine()
                    .getStatusCode());
        }
    }

    private String createJsonACLs(
            final List<Map<String, String>> principals_and_roles) {
        final Map<String, List<String>> acls =
                new HashMap<String, List<String>>();

        for (final Map<String, String> entries : principals_and_roles) {
            for (final Map.Entry<String, String> entry : entries.entrySet()) {
                acls.put(entry.getKey(), Collections.singletonList(entry
                        .getValue()));
            }
        }
        return makeJson(acls);
    }

    private static String makeJson(final Map<String, List<String>> roles) {
        final ObjectMapper mapper = new ObjectMapper();
        final StringWriter sw = new StringWriter();
        try {
            mapper.writeValue(sw, roles);
            return sw.toString();
        } catch (final IOException e) {
            throw new Error(e);
        }
    }

    private static List<BasicRolesPepTestObjectBean> defineTestObjects() {
        final List<BasicRolesPepTestObjectBean> test_objs =
                new ArrayList<BasicRolesPepTestObjectBean>();

        final BasicRolesPepTestObjectBean objA =
                new BasicRolesPepTestObjectBean();
        objA.setPath("testparent1");
        objA.addACL("everyone", "reader");
        objA.addACL("examplereader", "reader");
        objA.addACL("examplewriter", "writer");
        objA.addACL("examplewriter", "admin");
        objA.addDatastream("tsp1_data", "Test Parent 1, datastream 1,  Hello!");
        objA.addDatastream("tsp2_data",
                "Test Parent 1, datastream 2,  secret stuff");
        objA.addDatastreamACL("tsp2_data", "examplereader", "reader");
        objA.addDatastreamACL("tsp2_data", "examplewriter", "writer");
        objA.addDatastreamACL("tsp2_data", "exampleadmin", "admin");
        test_objs.add(objA);

        final BasicRolesPepTestObjectBean objB =
                new BasicRolesPepTestObjectBean();
        objB.setPath("testparent1/testchild1NoACL");
        objB.addDatastream("tsc1_data", "Test Child 1, datastream 1,  Hello!");
        test_objs.add(objB);

        final BasicRolesPepTestObjectBean objC =
                new BasicRolesPepTestObjectBean();
        objC.setPath("testparent1/testchild2WithACL");
        objC.addACL("examplereader", "reader");
        objC.addACL("examplewriter", "writer");
        objC.addACL("examplewriter", "admin");
        objC.addDatastream("tsc1_data",
                "Test Child 2, datastream 1,  really secret stuff");
        objC.addDatastream("tsc2_data",
                "Test Child 2, datastream 2,  really really secret stuff");
        objC.addDatastreamACL("tsc2_data", "examplewriter", "writer");
        objC.addDatastreamACL("tsc2_data", "exampleadmin", "admin");
        test_objs.add(objC);

        final BasicRolesPepTestObjectBean objD =
                new BasicRolesPepTestObjectBean();
        objD.setPath("testparent1/testchild4WithACL");
        objD.addACL("examplewriter", "writer");
        objD.addACL("examplewriter", "admin");
        objD.addDatastream("tsc1_data",
                "Test Child 3, datastream 1,  really secret stuff");
        objD.addDatastream("tsc2_data",
                "Test Child 3, datastream 2,  really really secret stuff");
        objD.addDatastreamACL("tsc2_data", "exampleadmin", "admin");

        final BasicRolesPepTestObjectBean objE =
                new BasicRolesPepTestObjectBean();
        objE.setPath("testparent1/testchild4WithACL");
        objE.addACL("examplewriter", "admin");
        objE.addDatastream("tsc1_data",
                "Test Child 4, datastream 1, burn before reading");
        objE.addDatastream("tsc2_data", "Test Child 4, datastream 2, Hello!");
        objE.addDatastreamACL("tsc2_data", "everyone", "reader");
        test_objs.add(objE);

        return test_objs;

    }
}
