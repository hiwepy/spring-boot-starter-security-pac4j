/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.http.ajax.AjaxRequestResolver;
import org.pac4j.core.http.ajax.DefaultAjaxRequestResolver;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

/**
 * This entry point can be defined with a security configuration and a client name:
 * if it's an indirect client, it redirects the user to te identity provider for login. Otherwise, a 401 error page is returned.
 * If no configuration is provided, an error is returned directly.
 *
 * @author Jerome Leleu
 * @since 1.0.0
 */
@SuppressWarnings({"rawtypes","unchecked"})
public class Pac4jEntryPoint extends DefaultSecurityLogic<Object, JEEContext> implements AuthenticationEntryPoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(Pac4jEntryPoint.class);

    private Config config;
    /** Specifies the name of the request parameter on where to find the clientName (i.e. client_name). */
  	private String clientParameterName = "client_name";
    private String defaultClientName;
    private AjaxRequestResolver ajaxRequestResolver = new DefaultAjaxRequestResolver();
    
    public Pac4jEntryPoint() {}
    
    public Pac4jEntryPoint(final Config config, final String clientName, final String clientParameterName) {
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
            final JEEContext context = new JEEContext(request, response, config.getSessionStore());
            final List<Client<? extends Credentials>> currentClients = new ArrayList<>();
            final Optional<Client> client = config.getClients().findClient(clientName);
            currentClients.add(client.get());

            try {
                if (startAuthentication(context, currentClients)) {
                	LOGGER.debug("Redirecting to identity provider for login");
                    saveRequestedUrl(context, currentClients, ajaxRequestResolver);
                    redirectToIdentityProvider(context, currentClients);
                } else {
                    unauthorized(context, currentClients);
                }
            } catch (final HttpAction e) {
            	LOGGER.debug("extra HTTP action required in Pac4jEntryPoint: {}", e.getCode());
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
