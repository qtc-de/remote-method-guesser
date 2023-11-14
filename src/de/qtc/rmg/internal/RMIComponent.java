package de.qtc.rmg.internal;

/**
 * The RMIComponent enum represents the different RMI components that may be targeted
 * when communicating with an RMI server. The enum contains the three well known components
 * Registry, Activator and DGC as well as a member named CUSTOM, that is used for not
 * well known remote objects.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum RMIComponent {

    ACTIVATOR("Activator", "act"),
    DGC("DGC", "dgc"),
    REGISTRY("Registry", "reg"),
    CUSTOM("RMI Endpoint", "endpoint");

    public String name;
    public String shortName;

    /**
     * RMIComponents consist out of a human readable name and a short name. Human readable names
     * are used within error messages. Short names are used for help messages and command line parsing.
     *
     * @param name Human readable name for the component
     * @param shortName Short name for the component (command line name)
     */
    RMIComponent(String name, String shortName)
    {
        this.name = name;
        this.shortName = shortName;
    }

    /**
     * Get the corresponding RMIComponent by specifying its short name.
     *
     * @param shortName Component shortName to look for
     * @return RMIComponent matching the shortName or null
     */
    public static RMIComponent getByShortName(String shortName)
    {
        for( RMIComponent component : RMIComponent.values() ) {

            if( component.shortName.equals(shortName) )
                return component;
        }

        return null;
    }
}
