
package org.fcrepo.auth.roles;

/**
 * @author Gregory Jansen
 */
public class Constants {

    public static enum JcrName {
        rbaclAssignable(), Rbacl(), Assignment();

        public static final String NS_URI =
                "http://fedora.info/definitions/v4/authorization#";

        public String getQualifiedName() {
            return NS_URI + this.name();
        }

        /*
         * (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return getQualifiedName();
        }

    }

    public static enum JcrPath {
        rbacl(), principal(), role();
    }
}
