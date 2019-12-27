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
package org.springframework.security.boot.pac4j.authentication;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.engine.CallbackLogic;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.pac4j.Pac4jCallbackUrlParser;
import org.springframework.security.boot.pac4j.profile.SpringSecurityProfileManager;
import org.springframework.security.boot.utils.ProfileUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

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

    private Pac4jCallbackUrlParser callbackUrlParser; 
    
	private RequestMatcher requiresAuthenticationRequestMatcher;

    public Pac4jPreAuthenticationCallbackFilter() {
        setSuffix(DEFAULT_CALLBACK_SUFFIX);
        callbackLogic = new DefaultCallbackLogic<>();
        ((DefaultCallbackLogic<Object, JEEContext>) callbackLogic).setProfileManagerFactory(SpringSecurityProfileManager::new);
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login/callback"));
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
    	
    	HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
 
		if (!requiresAuthentication(httpRequest, httpResponse)) {
			filterChain.doFilter(httpRequest, httpResponse);
			return;
		}
		
		if (logger.isDebugEnabled()) {
			logger.debug("Request is to process authentication");
		}
		
    	CommonHelper.assertNotNull("config", this.config);
    	
    	final JEEContext context = ProfileUtils.getJEEContext(request, response, config.getSessionStore());
    	
    	String callbackUrl = null;
        if( null != getCallbackUrlParser()) {
     	    Optional<String> customCallbackUrl = getCallbackUrlParser().parser(context);
     	    if(null != customCallbackUrl && customCallbackUrl.isPresent()) {
     	    	callbackUrl = customCallbackUrl.get();
     	    }
     	}
        if( null == callbackUrl) {
        	callbackUrl = this.defaultUrl;
        }
        
        if (mustApply(context)) {
        	
        	CommonHelper.assertNotNull("callbackLogic", this.callbackLogic);
        	
			callbackLogic.perform(context, this.config, JEEHttpActionAdapter.INSTANCE,
					callbackUrl, this.saveInSession, this.multiProfile, this.renewSession, this.defaultClient);
			
        } else {
        	
        	filterChain.doFilter(request, response);
        	
        }
        
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
    
    /**
   	 * Indicates whether this filter should attempt to process a login request for the
   	 * current invocation.
   	 * <p>
   	 * It strips any parameters from the "path" section of the request URL (such as the
   	 * jsessionid parameter in <em>https://host/myapp/index.html;jsessionid=blah</em>)
   	 * before matching against the <code>filterProcessesUrl</code> property.
   	 * <p>
   	 * Subclasses may override for special requirements, such as Tapestry integration.
   	 *
   	 * @return <code>true</code> if the filter should attempt authentication,
   	 * <code>false</code> otherwise.
   	 */
   	protected boolean requiresAuthentication(HttpServletRequest request,
   			HttpServletResponse response) {
   		return requiresAuthenticationRequestMatcher.matches(request);
   	}
   	
	/**
	 * Sets the URL that determines if authentication is required
	 *
	 * @param filterProcessesUrl
	 */
	public void setFilterProcessesUrl(String filterProcessesUrl) {
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher(
				filterProcessesUrl));
	}
   	
   	public final void setRequiresAuthenticationRequestMatcher(
   			RequestMatcher requestMatcher) {
   		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
   		this.requiresAuthenticationRequestMatcher = requestMatcher;
   	}

	public Pac4jCallbackUrlParser getCallbackUrlParser() {
		return callbackUrlParser;
	}

	public void setCallbackUrlParser(Pac4jCallbackUrlParser callbackUrlParser) {
		this.callbackUrlParser = callbackUrlParser;
	}

}