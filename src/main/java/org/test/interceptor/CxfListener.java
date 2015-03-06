package org.test.interceptor;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Interceptor;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CxfListener {

    private final static Logger LOGGER = LoggerFactory.getLogger(CxfListener.class);
    private ConfigurationAdmin configurationAdmin;
    private Interceptor insertLog;

    public void busRegistered(Bus bus) {
        InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        try {
            LOGGER.debug("Checking if CXF bus [{}] is defined in the configuration", bus.getId());
            if (util.busDefined(bus.getId())) {
                LOGGER.debug("Injecting interceptors on CXF bus {}", bus.getId());

                if (!bus.getInInterceptors().contains(insertLog)) {
                    bus.getInInterceptors().add(insertLog);
                }
            }
        } catch (Exception e) {
            LOGGER.error("Listener injection failed", e);
        }
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }


    public void setInsertLog(Interceptor insertLog) {
        this.insertLog = insertLog;
    }

}
