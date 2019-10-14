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
package org.springframework.security.boot.pac4j.authentication;


import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.engine.SecurityLogic;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.util.CommonHelper;
import org.springframework.security.boot.pac4j.profile.SpringSecurityProfileManager;
import org.springframework.security.boot.utils.ProfileUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

public class Pac4jPreAuthenticatedSecurityFilter extends AbstractPreAuthenticatedProcessingFilter {

	private SecurityLogic<Object, JEEContext> securityLogic;

    private Config config;

    private String clients;

    private String authorizers;

    private String matchers;

    private Boolean multiProfile;

    public Pac4jPreAuthenticatedSecurityFilter() {
        securityLogic = new DefaultSecurityLogic<>();
        ((DefaultSecurityLogic<Object, JEEContext>) securityLogic).setProfileManagerFactory(SpringSecurityProfileManager::new);
    }

    public Pac4jPreAuthenticatedSecurityFilter(final Config config) {
        this();
        this.config = config;
    }

    public Pac4jPreAuthenticatedSecurityFilter(final Config config, final String clients) {
        this(config);
        this.clients = clients;
    }

    public Pac4jPreAuthenticatedSecurityFilter(final Config config, final String clients, final String authorizers) {
        this(config, clients);
        this.authorizers = authorizers;
    }

    @Override
	public void afterPropertiesSet() {
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
			
		CommonHelper.assertNotNull("securityLogic", this.securityLogic);
		CommonHelper.assertNotNull("config", this.config);

        final JEEContext context = ProfileUtils.getJEEContext(request, response, config.getSessionStore());
        
        securityLogic.perform(context, this.config, (ctx, profiles, parameters) -> {

            filterChain.doFilter(request, response);
            return null;

        }, JEEHttpActionAdapter.INSTANCE, this.clients, this.authorizers, this.matchers, this.multiProfile);
		
	}

	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		return "N/A";
	}

	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}
	
	public SecurityLogic<Object, JEEContext> getSecurityLogic() {
        return securityLogic;
    }

    public void setSecurityLogic(final SecurityLogic<Object, JEEContext> securityLogic) {
        this.securityLogic = securityLogic;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(final Config config) {
        this.config = config;
    }

    public String getClients() {
        return clients;
    }

    public void setClients(final String clients) {
        this.clients = clients;
    }

    public String getAuthorizers() {
        return authorizers;
    }

    public void setAuthorizers(final String authorizers) {
        this.authorizers = authorizers;
    }

    public String getMatchers() {
        return matchers;
    }

    public void setMatchers(final String matchers) {
        this.matchers = matchers;
    }

    public Boolean getMultiProfile() {
        return multiProfile;
    }

    public void setMultiProfile(final Boolean multiProfile) {
        this.multiProfile = multiProfile;
    }

}