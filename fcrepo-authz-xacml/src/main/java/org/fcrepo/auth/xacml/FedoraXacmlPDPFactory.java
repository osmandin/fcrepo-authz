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

import java.util.HashSet;
import java.util.Set;

import javax.annotation.PostConstruct;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.PolicyLocator;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.locators.JBossPolicyLocator;

/**
 * @author Gregory Jansen
 *
 */
public class FedoraXacmlPDPFactory {

    private PolicyDecisionPoint pdp = null;

    /**
     * Initialize a PDP and load policies
     *
     * @throws Exception if PDP cannot be initialized
     */
    @PostConstruct
    public void init() throws Exception {
        final PolicyType policyType =
                BasicJavaPolicyFactory.constructReaderPolicy();
        pdp = new JBossPDP();

        final XACMLPolicy policy = PolicyFactory.createPolicy(policyType);
        final Set<XACMLPolicy> policies = new HashSet<XACMLPolicy>();
        policies.add(policy);

        pdp.setPolicies(policies);

        // Add the basic locators also
        final Set<PolicyLocator> locators = new HashSet<PolicyLocator>();
        final PolicyLocator policyLocator = new JBossPolicyLocator();

        // Locators need to be given the policies
        policyLocator.setPolicies(policies);

        locators.add(policyLocator);

        pdp.setLocators(locators);
    }

    /**
     * @return the XACML Policy Decision Point
     */
    public PolicyDecisionPoint getPDP() {
        return this.pdp;
    }

}
