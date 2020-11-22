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
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.engine.SecurityLogic;
import org.pac4j.core.http.adapter.JEEHttpActionAdapter;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.boot.pac4j.Pac4jProxyReceptor;
import org.springframework.security.boot.pac4j.Pac4jRedirectionUrlParser;
import org.springframework.security.boot.pac4j.profile.SpringSecurityProfileManager;
import org.springframework.security.boot.utils.ProfileUtils;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class Pac4jPreAuthenticatedSecurityFilter extends AbstractPreAuthenticatedProcessingFilter {

	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	private SecurityLogic<Object, JEEContext> securityLogic;

    private Config config;

    private String clients;

    private String authorizers;

    private String matchers;

    private Boolean multiProfile;

	private RequestMatcher requiresAuthenticationRequestMatcher;
	
	private Pac4jProxyReceptor proxyReceptor;
	
	private Pac4jAuthorizationTokenGenerator tokenGenerator;

    private Pac4jRedirectionUrlParser redirectionUrlParser;
    
	/**
	 * Define on which error URL the user will be redirected in case of an exception.
	 */
	private String errorUrl;
	
    public Pac4jPreAuthenticatedSecurityFilter() {
        securityLogic = new DefaultSecurityLogic<>();
        ((DefaultSecurityLogic<Object, JEEContext>) securityLogic).setProfileManagerFactory(SpringSecurityProfileManager::new);
        setFilterProcessesUrl("/login/pac4j");
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
		
		CommonHelper.assertNotNull("securityLogic", this.securityLogic);
		CommonHelper.assertNotNull("config", this.config);
		
		// Set RequestContextHolder
		ServletRequestAttributes requestAttributes = new ServletRequestAttributes(httpRequest, httpResponse);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
				
        final JEEContext context = ProfileUtils.getJEEContext(request, response, config.getSessionStore());

        if(securityLogic instanceof DefaultSecurityLogic && StringUtils.hasText(errorUrl)) {
        	
        	String errorUrl = null;
            if( null != getRedirectionUrlParser()) {
         	    Optional<String> customErrorUrl = getRedirectionUrlParser().errorUrl(context);
         	    if(null != customErrorUrl && customErrorUrl.isPresent()) {
         	    	errorUrl = customErrorUrl.get();
         	    }
         	}
            if( null == errorUrl) {
            	errorUrl = this.errorUrl;
            }
            
        	((DefaultSecurityLogic<Object, JEEContext>) securityLogic).setErrorUrl(errorUrl);
        }

		securityLogic.perform(context, this.config, (ctx, profiles, parameters) -> {
			// 前后端分离模式下的前端跳转代理：解决认证成功后携带认证信息到前端服务问题
			if (proxyReceptor != null) {
				logger.debug("proxyReceptor : {}", proxyReceptor.getClass());
				return proxyReceptor.getRedirectionAction(ctx);
			} 
			
			else {
				
				logger.debug("filterChain doFilter: {}", filterChain.getClass());
				
				filterChain.doFilter(request, response);
				return null;
			}
		}, JEEHttpActionAdapter.INSTANCE, this.clients, this.authorizers, this.matchers, this.multiProfile);
		
	}

	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		return "N/A";
	}

	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}
	
	public Pac4jProxyReceptor getProxyReceptor() {
		return proxyReceptor;
	}
	
	public Pac4jAuthorizationTokenGenerator getTokenGenerator() {
		return tokenGenerator;
	}

	public void setTokenGenerator(Pac4jAuthorizationTokenGenerator tokenGenerator) {
		this.tokenGenerator = tokenGenerator;
	}

	public void setProxyReceptor(Pac4jProxyReceptor proxyReceptor) {
		this.proxyReceptor = proxyReceptor;
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
    
    public String getErrorUrl() {
		return errorUrl;
	}

	public void setErrorUrl(String errorUrl) {
		this.errorUrl = errorUrl;
	}

	/*
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
	
   	public Pac4jRedirectionUrlParser getRedirectionUrlParser() {
		return redirectionUrlParser;
	}

	public void setRedirectionUrlParser(Pac4jRedirectionUrlParser redirectionUrlParser) {
		this.redirectionUrlParser = redirectionUrlParser;
	}

}