package org.test.interceptor;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Interceptor;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Inject interceptor in the CXF buses
 */
public class InterceptorsInjector {

    private final static Logger LOGGER = LoggerFactory.getLogger(InterceptorsInjector.class);

    private List<Bus> buses;
    private ConfigurationAdmin configurationAdmin;

    private Interceptor insertLog;

    public void inject() {
        InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        try {
            for (Bus bus : buses) {
                LOGGER.info("Checking if CXF bus [{}] is defined in the configuration", bus.getId());
                if (util.busDefined(bus.getId())) {
                    LOGGER.info("Injecting interceptor on CXF bus [{}]", bus.getId());

               if (!bus.getInInterceptors().contains(insertLog)) {
                        bus.getInInterceptors().add(insertLog);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Injection failed", e);
        }
    }

    public void setBuses(List<Bus> busses) {
        this.buses = busses;
    }

    public List<Bus> getBuses() {
        return this.buses;
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return this.configurationAdmin;
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

    public void setInsertLog(Interceptor insertLog) {
        this.insertLog = insertLog;
    }

/*XMT
    public Interceptor getAuthenticator() {
        return this.authenticator;
    }
XMT*/
}
