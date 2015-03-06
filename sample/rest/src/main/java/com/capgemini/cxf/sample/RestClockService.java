package com.capgemini.cxf.sample;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/")
public class RestClockService {

    @GET
    @Path("/current")
    public String currentTime() throws Exception {
        return "Time " + System.currentTimeMillis();
    }

}
