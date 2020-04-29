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
package org.springframework.security.boot.pac4j;

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.redirect.RedirectionActionBuilder;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.spring.boot.utils.Pac4jUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.pac4j.authentication.Pac4jAuthenticationPrincipalToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class Pac4jRedirectionActionBuilder implements RedirectionActionBuilder {

    private static final Logger logger = LoggerFactory.getLogger(Pac4jRedirectionActionBuilder.class);
    
    /**
  	 * The location of the front-end server login URL, 
  	 * i.e. 
  	 * http://localhost:8080/#/client
  	 * http://localhost:8080/#/client?client_name=cas
  	 */
    private String callbackUrl;
    private String targetUrlParameter = null;
	private String defaultTargetUrl = "/";
	private boolean alwaysUseDefaultTargetUrl = false;
	private boolean useReferer = false;
	
    private JwtPayloadRepository jwtPayloadRepository;
    private UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private Pac4jRedirectionUrlParser redirectionUrlParser; 
    
    public Pac4jRedirectionActionBuilder() {
    }
     

	
    @Override
    public Optional<RedirectionAction> getRedirectionAction(final WebContext context) {
    	
    	CommonHelper.assertNotNull("jwtPayloadRepository", jwtPayloadRepository);
    	CommonHelper.assertNotNull("userDetailsService", userDetailsService);
    	CommonHelper.assertNotNull("userDetailsChecker", userDetailsChecker);
    	
    	// 获取上下文
    	JEEContext jeeContext = (JEEContext) context;

    	// 获取已经认证的对象
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CommonHelper.assertNotNull("authenticationToken", authentication);
        
        // 查询用户详情
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        // 构造权限token
        Pac4jAuthenticationPrincipalToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	authenticationToken = new Pac4jAuthenticationPrincipalToken(ud, ud.getPassword(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new Pac4jAuthenticationPrincipalToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        // 签发jwt
    	String tokenString = getJwtPayloadRepository().issueJwt(authenticationToken);
    	
    	String redirectionUrl = null;
        if( null != redirectionUrlParser) {
     	    Optional<String> customRedirectionUrl = redirectionUrlParser.redirectUrl(jeeContext, authentication);
     	    if(null != customRedirectionUrl && customRedirectionUrl.isPresent()) {
     	    	redirectionUrl = customRedirectionUrl.get();
     	    }
     	}
        if( null == redirectionUrl) {
        	redirectionUrl = callbackUrl;
        }
        
        // 重定向后的跳转地址
        redirectionUrl = CommonHelper.addParameter(redirectionUrl, "target", this.determineTargetUrl(jeeContext));
        redirectionUrl = CommonHelper.addParameter(redirectionUrl, "token", tokenString);
        logger.debug("redirectionUrl: {}", redirectionUrl);
        
        Pac4jUrlUtils.sendRedirect(jeeContext.getNativeResponse(), redirectionUrl);
        
        //return Optional.of(RedirectionActionHelper.buildRedirectUrlAction(context, redirectionUrl));
        return Optional.empty();
    }

	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	protected String determineTargetUrl(WebContext context) {
		if (isAlwaysUseDefaultTargetUrl()) {
			return defaultTargetUrl;
		}

		// Check for the parameter and use that if available
		String targetUrl = null;

		if (targetUrlParameter != null) {
			targetUrl = context.getRequestParameter(targetUrlParameter).orElse("");
			if (StringUtils.isNotBlank(targetUrl)) {
				logger.debug("Found targetUrlParameter in request: " + targetUrl);
				return targetUrl;
			}
		}

		if (useReferer && !StringUtils.isNotBlank(targetUrl)) {
			targetUrl = context.getRequestHeader("Referer").orElse("");
			logger.debug("Using Referer header: " + targetUrl);
		}

		if (!StringUtils.isNotBlank(targetUrl)) {
			targetUrl = defaultTargetUrl;
			logger.debug("Using default Url: " + targetUrl);
		}

		return targetUrl;
	}

	/**
	 * Supplies the default target Url that will be used if no saved request is found or
	 * the {@code alwaysUseDefaultTargetUrl} property is set to true. If not set, defaults
	 * to {@code /}.
	 *
	 * @return the defaultTargetUrl property
	 */
	protected final String getDefaultTargetUrl() {
		return defaultTargetUrl;
	}

	/**
	 * Supplies the default target Url that will be used if no saved request is found in
	 * the session, or the {@code alwaysUseDefaultTargetUrl} property is set to true. If
	 * not set, defaults to {@code /}. It will be treated as relative to the web-app's
	 * context path, and should include the leading <code>/</code>. Alternatively,
	 * inclusion of a scheme name (such as "http://" or "https://") as the prefix will
	 * denote a fully-qualified URL and this is also supported.
	 *
	 * @param defaultTargetUrl
	 */
	public void setDefaultTargetUrl(String defaultTargetUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultTargetUrl),
				"defaultTarget must start with '/' or with 'http(s)'");
		this.defaultTargetUrl = defaultTargetUrl;
	}

	/**
	 * If <code>true</code>, will always redirect to the value of {@code defaultTargetUrl}
	 * (defaults to <code>false</code>).
	 */
	public void setAlwaysUseDefaultTargetUrl(boolean alwaysUseDefaultTargetUrl) {
		this.alwaysUseDefaultTargetUrl = alwaysUseDefaultTargetUrl;
	}

	protected boolean isAlwaysUseDefaultTargetUrl() {
		return alwaysUseDefaultTargetUrl;
	}

	/**
	 * If this property is set, the current request will be checked for this a parameter
	 * with this name and the value used as the target URL if present.
	 *
	 * @param targetUrlParameter the name of the parameter containing the encoded target
	 * URL. Defaults to null.
	 */
	public void setTargetUrlParameter(String targetUrlParameter) {
		if (targetUrlParameter != null) {
			Assert.hasText(targetUrlParameter, "targetUrlParameter cannot be empty");
		}
		this.targetUrlParameter = targetUrlParameter;
	}

	protected String getTargetUrlParameter() {
		return targetUrlParameter;
	}
	
	public String getCallbackUrl() {
		return callbackUrl;
	}

	public void setCallbackUrl(String callbackUrl) {
		this.callbackUrl = callbackUrl;
	}
	 
	public Pac4jRedirectionUrlParser getRedirectionUrlParser() {
		return redirectionUrlParser;
	}

	public void setRedirectionUrlParser(Pac4jRedirectionUrlParser redirectionUrlParser) {
		this.redirectionUrlParser = redirectionUrlParser;
	}

	public JwtPayloadRepository getJwtPayloadRepository() {
		return jwtPayloadRepository;
	}

	public void setJwtPayloadRepository(JwtPayloadRepository jwtPayloadRepository) {
		this.jwtPayloadRepository = jwtPayloadRepository;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}

	public void setUserDetailsService(UserDetailsServiceAdapter userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}
	
}
