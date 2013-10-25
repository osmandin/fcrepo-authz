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

import static org.junit.Assert.assertTrue;

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

    @Test
    public void testUnauthenticatedReaderCanReadEveryoneObj() throws ClientProtocolException, IOException {
        assertTrue("Reader can read testparent1", canRead(null, "testparent1",
                false));
    }

    @Test
    public void sampleTestAuthenticatedReaderCanReadEveryoneObj()
            throws ClientProtocolException, IOException {
        assertTrue("Reader can read testparent1", canRead("examplereader",
                "testparent1", true));
    }
}
