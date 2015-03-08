package org.test.interceptor.Basic;


import org.test.interceptor.InterceptorsUtil;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.ws.security.handler.RequestData;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * This interceptor just log when it's called
 */
public class BasicInterceptor extends AbstractPhaseInterceptor<Message> {

    private final Logger LOGGER = LoggerFactory.getLogger(BasicInterceptor.class);

    private ConfigurationAdmin configurationAdmin;


    public BasicInterceptor() {
        this(Phase.UNMARSHAL);
    }

    public BasicInterceptor(String phase) {
        super(phase);
    }

    public void handleMessage(Message message) throws Fault {

        try {
            RequestData data = new RequestData();
            data.setMsgContext(message);

            LOGGER.info("This is a basic interceptor [{}] test : {}",this.getPhase(), data.toString());

            // create the util and retrieve WebService Id
            InterceptorsUtil util = new InterceptorsUtil(configurationAdmin);
        } catch (Exception ex) {
            throw new Fault(ex);
        }
    }

    public ConfigurationAdmin getConfigurationAdmin() {
        return configurationAdmin;
    }

    public void setConfigurationAdmin(ConfigurationAdmin configurationAdmin) {
        this.configurationAdmin = configurationAdmin;
    }

}
