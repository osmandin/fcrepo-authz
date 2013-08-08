package org.fcrepo.authz.pdp;

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
