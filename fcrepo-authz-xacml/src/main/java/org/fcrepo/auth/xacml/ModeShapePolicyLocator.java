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

import java.util.List;
import java.util.Set;

import org.jboss.security.xacml.interfaces.PolicyLocator;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.jaxb.Option;


/**
 * @author Gregory Jansen
 *
 */
public class ModeShapePolicyLocator implements PolicyLocator {

	/* (non-Javadoc)
	 * @see org.jboss.security.xacml.interfaces.AbstractLocator#setOptions(java.util.List)
	 */
	@Override
	public void setOptions(List<Option> arg0) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.jboss.security.xacml.interfaces.ContextMapOp#get(java.lang.String)
	 */
	@Override
	public <T> T get(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.jboss.security.xacml.interfaces.ContextMapOp#set(java.lang.String, java.lang.Object)
	 */
	@Override
	public <T> void set(String arg0, T arg1) {
		// TODO Auto-generated method stub

	}

	/* (non-Javadoc)
	 * @see org.jboss.security.xacml.interfaces.PolicyLocator#getPolicies()
	 */
	@Override
	public Set<XACMLPolicy> getPolicies() {
		// TODO Auto-generated method stub
		return null;
	}

	/* (non-Javadoc)
	 * @see org.jboss.security.xacml.interfaces.PolicyLocator#setPolicies(java.util.Set)
	 */
	@Override
	public void setPolicies(Set<XACMLPolicy> arg0) {
		// TODO Auto-generated method stub

	}

}
