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
package org.springframework.security.boot.pac4j.authentication.logout;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.session.JEESessionStore;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.engine.DefaultLogoutLogic;
import org.pac4j.core.engine.LogoutLogic;
import org.pac4j.core.http.adapter.HttpActionAdapter;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.core.util.FindBest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

public class Pac4jLogoutHandler implements LogoutHandler {

	protected final Logger logger = LoggerFactory.getLogger(getClass());

	private LogoutLogic<Object, JEEContext> logoutLogic;

    private Config config;

    private String defaultUrl;

    private String logoutUrlPattern;

    private Boolean localLogout;

    private Boolean destroySession;

    private Boolean centralLogout;

	public Pac4jLogoutHandler(final Config config, LogoutLogic<Object, JEEContext> logoutLogic) {
		this.config = config;
		this.logoutLogic = logoutLogic;
	}

	public Pac4jLogoutHandler(final Config config, LogoutLogic<Object, JEEContext> logoutLogic, final String defaultUrl) {
		this(config, logoutLogic);
		this.defaultUrl = defaultUrl;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

		CommonHelper.assertNotNull("logoutLogic", logoutLogic);
		
		final Config config = getConfig();
		CommonHelper.assertNotNull("config", config);
		
		final SessionStore<JEEContext> bestSessionStore = FindBest.sessionStore(null, config, JEESessionStore.INSTANCE);
        final HttpActionAdapter<Object, JEEContext> bestAdapter = FindBest.httpActionAdapter(null, config, JEEHttpActionAdapter.INSTANCE);
        final LogoutLogic<Object, JEEContext> bestLogic = FindBest.logoutLogic(logoutLogic, config, DefaultLogoutLogic.INSTANCE);

        final JEEContext context = new JEEContext(request, response, bestSessionStore);
        
        bestLogic.perform(context, config, bestAdapter, this.getDefaultUrl(),
				this.getLogoutUrlPattern(), this.isLocalLogout(), this.isDestroySession(), this.isCentralLogout());

	}

	public LogoutLogic<Object, JEEContext> getLogoutLogic() {
		return logoutLogic;
	}

	public void setLogoutLogic(LogoutLogic<Object, JEEContext> logoutLogic) {
		this.logoutLogic = logoutLogic;
	}

	public Config getConfig() {
		return config;
	}

	public void setConfig(Config config) {
		this.config = config;
	}

	public String getDefaultUrl() {
		return defaultUrl;
	}

	public void setDefaultUrl(String defaultUrl) {
		this.defaultUrl = defaultUrl;
	}

	public String getLogoutUrlPattern() {
		return logoutUrlPattern;
	}

	public void setLogoutUrlPattern(String logoutUrlPattern) {
		this.logoutUrlPattern = logoutUrlPattern;
	}

	public boolean isLocalLogout() {
		return localLogout;
	}

	public void setLocalLogout(boolean localLogout) {
		this.localLogout = localLogout;
	}

	public boolean isDestroySession() {
		return destroySession;
	}

	public void setDestroySession(boolean destroySession) {
		this.destroySession = destroySession;
	}

	public boolean isCentralLogout() {
		return centralLogout;
	}

	public void setCentralLogout(boolean centralLogout) {
		this.centralLogout = centralLogout;
	}

}
