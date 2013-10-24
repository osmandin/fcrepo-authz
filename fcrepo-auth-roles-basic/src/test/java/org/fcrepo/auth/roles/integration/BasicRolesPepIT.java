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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that roles are properly enforced.
 *
 * @author Gregory Jansen
 */
public class BasicRolesPepIT extends AbstractBasicRolesIT {

    private static final Logger logger = LoggerFactory
            .getLogger(BasicRolesPepIT.class);

    // @Test
    // public void testReader() throws ClientProtocolException, IOException {
    // assertTrue("Reader can read " + test, canRead("examplereader", test));
    // assertTrue("Reader can read " + test + "/" + testDS, canRead(
    // "examplereader", test + "/" + testDS));
    // assertFalse("Reader cannot read " + test + "/" + testAdminDS, canRead(
    // "examplereader", test + "/" + testAdminDS));
    // assertFalse("Reader cannot write", canAddDS("examplereader", test,
    // "foo"));
    // // assertFalse("Reader cannot write", canSetProperties("examplereader",
    // // test + "/" + testAdminDS));
    // // assertFalse("Reader cannot write", canSetRoles(
    // // "examplereader", test + "/" + testAdminDS));
    // }

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
