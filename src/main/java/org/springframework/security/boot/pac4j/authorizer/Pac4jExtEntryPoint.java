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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.config.Config;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.springframework.security.web.Pac4jEntryPoint;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

public class Pac4jExtEntryPoint extends Pac4jEntryPoint {

	/**
	 * Specifies the name of the request parameter on where to find the clientName (i.e. client_name).
	 */
	private String clientParameterName = "client_name";

	public Pac4jExtEntryPoint() {
	}

	public Pac4jExtEntryPoint(final Config config, final String clientName, final String clientParameterName) {
		super(config, clientName);
		this.clientParameterName = clientParameterName;
	}

	@Override
	public void commence(final HttpServletRequest request, final HttpServletResponse response,
			final AuthenticationException authException) throws IOException, ServletException {
		String defaultClientName = super.getClientName();
		String clientName = obtainClient(request);
		super.setClientName(StringUtils.hasText(clientName) ? clientName : defaultClientName);
		super.commence(request, response, authException);
	}

	protected String obtainClient(HttpServletRequest request) {
		return request.getParameter(getClientParameterName());
	}

	public String getClientParameterName() {
		return clientParameterName;
	}

	public void setClientParameterName(String clientParameterName) {
		this.clientParameterName = clientParameterName;
	}

	@Override
	public String toString() {
		return CommonHelper.toNiceString(this.getClass(), "config", getConfig(), "clientName", getClientName(),
				"clientParameterName", getClientParameterName());
	}

}
