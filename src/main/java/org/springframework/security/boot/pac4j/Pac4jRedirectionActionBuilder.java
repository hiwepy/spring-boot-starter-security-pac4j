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
	
    private JwtPayloadRepository jwtPayloadRepository;
    private UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private Pac4jRedirectionUrlParser redirectionUrlParser; 
    
    public Pac4jRedirectionActionBuilder() {
    }
     
    @Override
    public Optional<RedirectionAction> getRedirectionAction(WebContext context) {
    	
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
        redirectionUrl = CommonHelper.addParameter(redirectionUrl, "token", tokenString);
        logger.debug("redirectionUrl: {}", redirectionUrl);
        
        Pac4jUrlUtils.sendRedirect(jeeContext.getNativeResponse(), redirectionUrl);
        
        //return Optional.of(RedirectionActionHelper.buildRedirectUrlAction(context, redirectionUrl));
        return Optional.empty();
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
