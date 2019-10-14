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
import org.pac4j.core.engine.CallbackLogic;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.pac4j.profile.SpringSecurityProfileManager;
import org.springframework.security.boot.utils.ProfileUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

public class Pac4jPreAuthenticationCallbackFilter extends AbstractPreAuthenticatedProcessingFilter {

	protected final Logger logger = LoggerFactory.getLogger(getClass());

    public final static String DEFAULT_CALLBACK_SUFFIX = "/callback";

    private CallbackLogic<Object, JEEContext> callbackLogic;

    private Config config;

    private String defaultUrl;

    private Boolean saveInSession;

    private Boolean multiProfile;

    private Boolean renewSession;

    private String defaultClient;

    private String suffix;

    public Pac4jPreAuthenticationCallbackFilter() {
        setSuffix(DEFAULT_CALLBACK_SUFFIX);
        callbackLogic = new DefaultCallbackLogic<>();
        ((DefaultCallbackLogic<Object, JEEContext>) callbackLogic).setProfileManagerFactory(SpringSecurityProfileManager::new);
    }

    public Pac4jPreAuthenticationCallbackFilter(final Config config) {
        this();
        this.config = config;
    }

    public Pac4jPreAuthenticationCallbackFilter(final Config config, final String defaultUrl) {
        this(config);
        this.defaultUrl = defaultUrl;
    }

    public Pac4jPreAuthenticationCallbackFilter(final Config config, final String defaultUrl, final boolean multiProfile) {
        this(config, defaultUrl);
        this.multiProfile = multiProfile;
    }

    public Pac4jPreAuthenticationCallbackFilter(final Config config, final String defaultUrl, final boolean multiProfile, final boolean renewSession) {
        this(config, defaultUrl, multiProfile);
        this.renewSession = renewSession;
    }

    @Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

    	CommonHelper.assertNotNull("config", this.config);
    	
    	final JEEContext context = ProfileUtils.getJEEContext(request, response, config.getSessionStore());
    	
        if (mustApply(context)) {
        	CommonHelper.assertNotNull("callbackLogic", this.callbackLogic);
            callbackLogic.perform(context, this.config, JEEHttpActionAdapter.INSTANCE, this.defaultUrl, this.saveInSession,
                    this.multiProfile, this.renewSession, this.defaultClient);
        } else {
        	filterChain.doFilter(request, response);
        }
        
    }
    
    @Override
   	public void afterPropertiesSet() {
   	}

	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		return ProfileUtils.getAuthentication().getPrincipal();
	}

	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return ProfileUtils.getAuthentication().getCredentials();
	}
    
	protected boolean mustApply(final JEEContext context) {
        final String path = context.getPath();
        logger.debug("path: {} | suffix: {}", path, suffix);

        if (CommonHelper.isBlank(suffix)) {
            return true;
        } else {
            return path != null && path.endsWith(suffix);
        }
    }

    public String getSuffix() {
        return suffix;
    }

    public void setSuffix(final String suffix) {
        this.suffix = suffix;
    }
    
    public CallbackLogic<Object, JEEContext> getCallbackLogic() {
        return callbackLogic;
    }

    public void setCallbackLogic(final CallbackLogic<Object, JEEContext> callbackLogic) {
        this.callbackLogic = callbackLogic;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(final Config config) {
        this.config = config;
    }

    public String getDefaultUrl() {
        return defaultUrl;
    }

    public void setDefaultUrl(final String defaultUrl) {
        this.defaultUrl = defaultUrl;
    }

    public Boolean getMultiProfile() {
        return multiProfile;
    }

    public void setMultiProfile(final Boolean multiProfile) {
        this.multiProfile = multiProfile;
    }

    public Boolean getRenewSession() {
        return renewSession;
    }

    public void setRenewSession(final Boolean renewSession) {
        this.renewSession = renewSession;
    }

    public Boolean getSaveInSession() {
        return saveInSession;
    }

    public void setSaveInSession(final Boolean saveInSession) {
        this.saveInSession = saveInSession;
    }

    public String getDefaultClient() {
        return defaultClient;
    }

    public void setDefaultClient(final String defaultClient) {
        this.defaultClient = defaultClient;
    }

}