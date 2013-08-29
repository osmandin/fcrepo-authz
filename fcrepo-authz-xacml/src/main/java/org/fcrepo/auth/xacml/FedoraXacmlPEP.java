
package org.fcrepo.auth.xacml;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;

import org.apache.commons.lang.NotImplementedException;
import org.fcrepo.auth.FedoraPolicyEnforcementPoint;
import org.modeshape.jcr.value.Path;

/**
 * @author Gregory Jansen
 */
public class FedoraXacmlPEP implements FedoraPolicyEnforcementPoint {

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPdp#hasModeShapePermission(org.fcrepo.auth.Path,
     * java.lang.String[], java.util.Set, java.security.Principal)
     */
    @Override
    public boolean hasModeShapePermission(final Path absPath,
            final String[] actions, final Set<Principal> groupPrincipals,
            final Principal userPrincipal) {
        return false;
    }

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPolicyEnforcementPoint#filterPathsForReading(java
     * .util.Collection, java.util.Set, java.security.Principal)
     */
    @Override
    public Set<Path> filterPathsForReading(final Collection<Path> paths,
            final Set<Principal> allPrincipals,
            final Principal userPrincipal) {
        // TODO delegate this permission check to the PDP.
        throw new NotImplementedException();
    }

}
