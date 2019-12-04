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
package org.springframework.security.boot.pac4j;

import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.BooleanUtils;
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
import org.springframework.util.CollectionUtils;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */
public class Pac4jRedirectionActionBuilder implements RedirectionActionBuilder {

    private static final Logger logger = LoggerFactory.getLogger(Pac4jRedirectionActionBuilder.class);
    
    /**
  	 * The location of the front-end server login URL, 
  	 * i.e. 
  	 * http://localhost:8080/#/client?target=/portal
  	 * http://localhost:8080/#/client?client_name=cas&target=/portal
  	 */
    private String callbackUrl;
    /**
  	 * The location of the front-end server login URL, 
  	 * i.e. 
  	 * http://localhost:8080/#/client?target=/portal
  	 * http://localhost:8080/#/client?client_name=cas&target=/portal
  	 */
    private String callbackH5Url;
    private List<String> h5RedirectList;
    private JwtPayloadRepository jwtPayloadRepository;
    private UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    
    public Pac4jRedirectionActionBuilder() {
    }
    
    @Override
    public Optional<RedirectionAction> redirect(final WebContext context) {
    	
    	CommonHelper.assertNotNull("jwtPayloadRepository", jwtPayloadRepository);
    	CommonHelper.assertNotNull("userDetailsService", userDetailsService);
    	CommonHelper.assertNotNull("userDetailsChecker", userDetailsChecker);
    	
    	// 获取上下文
    	JEEContext jeeContext = (JEEContext) context;

    	// 获取已经认证的对象
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        CommonHelper.assertNotNull("authenticationToken", authentication);
        
        boolean isH5 = false;
        Optional<String > optional = jeeContext.getRequestParameter("h5");
        if(optional.isPresent()) {
        	isH5 = BooleanUtils.toBoolean(optional.get());
        }
        
        CommonHelper.assertNotNull("callbackUrl", isH5 ? callbackH5Url : callbackUrl);
        
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
    	
    	// 判断是否是H5网站
    	if(!CollectionUtils.isEmpty(this.getH5RedirectList())) {
    		for (String redirectionUrl : this.getH5RedirectList()) {
    			if(StringUtils.startsWith(context.getPath(), redirectionUrl) || StringUtils.startsWith(context.getFullRequestURL(), redirectionUrl)) {
    				isH5 = true;
    				break;
    			}
			}
    	}
    	
    	// 重定向
        final String redirectionUrl = CommonHelper.addParameter(isH5 ? callbackH5Url : callbackUrl, "token", tokenString);
        logger.debug("redirectionUrl: {}", redirectionUrl);
        
        Pac4jUrlUtils.sendRedirect(jeeContext.getNativeResponse(), redirectionUrl);
        
        return Optional.empty();
    }

	public String getCallbackUrl() {
		return callbackUrl;
	}

	public void setCallbackUrl(String callbackUrl) {
		this.callbackUrl = callbackUrl;
	}
	
	public String getCallbackH5Url() {
		return callbackH5Url;
	}

	public void setCallbackH5Url(String callbackH5Url) {
		this.callbackH5Url = callbackH5Url;
	}

	public List<String> getH5RedirectList() {
		return h5RedirectList;
	}

	public void setH5RedirectList(List<String> h5RedirectList) {
		this.h5RedirectList = h5RedirectList;
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
