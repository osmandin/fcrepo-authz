
package org.fcrepo.auth.integration;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;

import org.fcrepo.auth.FedoraPolicyEnforcementPoint;
import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Gregory Jansen
 */
public class PermitWhereNodeStartsWithPermitPEP implements
        FedoraPolicyEnforcementPoint {

    Logger logger = LoggerFactory
            .getLogger(PermitWhereNodeStartsWithPermitPEP.class);

    /*
     * (non-Javadoc)
     * @see
     * org.fcrepo.auth.FedoraPolicyEnforcementPoint#hasModeShapePermission(org
     * .modeshape.jcr.value.Path, java.lang.String[], java.util.Set,
     * java.security.Principal)
     */
    @Override
    public boolean hasModeShapePermission(final Path absPath,
            final String[] actions, final Set<Principal> allPrincipals,
            final Principal userPrincipal) {

        if (absPath.isRoot()) {
            return true;
        }
        return absPath.getLastSegment().getName().getString().startsWith(
                "Permit");
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
        return null;
    }

}
