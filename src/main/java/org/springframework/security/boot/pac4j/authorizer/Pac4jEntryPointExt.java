/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.pac4j.authorizer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.util.CommonHelper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class Pac4jEntryPointExt extends DefaultSecurityLogic<Object, J2EContext> implements AuthenticationEntryPoint {

    private Config config;
    /** Specifies the name of the request parameter on where to find the clientName (i.e. client_name). */
	private String clientParameterName = "client_name";
    private String defaultClientName;

    public Pac4jEntryPointExt() {}

    public Pac4jEntryPointExt(final Config config, final String clientName, final String clientParameterName) {
        this.config = config;
        this.defaultClientName = clientName;
        this.clientParameterName = clientParameterName;
    }

	@Override
    public void commence(final HttpServletRequest request, final HttpServletResponse response,
                         final AuthenticationException authException) throws IOException, ServletException {

    	// 从请求地址中获取clientName
    	String clientName = obtainClient(request);
    		   clientName = StringUtils.hasText(clientName) ? clientName : defaultClientName;
    	
        if (config != null && CommonHelper.isNotBlank(clientName)) {
            final J2EContext context = new J2EContext(request, response, config.getSessionStore());
            final List<Client> currentClients = new ArrayList<>();
            final Client client = config.getClients().findClient(clientName);
            currentClients.add(client);

            try {
                if (startAuthentication(context, currentClients)) {
                    logger.debug("Redirecting to identity provider for login");
                        saveRequestedUrl(context, currentClients);
                        redirectToIdentityProvider(context, currentClients);
                } else {
                    unauthorized(context, currentClients);
                }
            } catch (final HttpAction e) {
                logger.debug("extra HTTP action required in Pac4jEntryPoint: {}", e.getCode());
            }

        } else {
            throw new TechnicalException("The Pac4jEntryPoint has been defined without config, nor clientName: it must be defined in a <security:http> section with the pac4j SecurityFilter or CallbackFilter");
        }
    }
    
    protected String obtainClient(HttpServletRequest request) {
		return request.getParameter(getClientParameterName());
	}

    public Config getConfig() {
        return config;
    }

    public void setConfig(final Config config) {
        this.config = config;
    }

    public String getClientParameterName() {
		return clientParameterName;
	}

	public void setClientParameterName(String clientParameterName) {
		this.clientParameterName = clientParameterName;
	}

	@Override
    public String toString() {
        return CommonHelper.toNiceString(this.getClass(), "config", config, "clientName", defaultClientName);
    }
	
}
