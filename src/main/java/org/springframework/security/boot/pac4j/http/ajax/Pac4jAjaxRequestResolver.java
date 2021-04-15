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
package org.springframework.security.boot.pac4j.http.ajax;

import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.exception.http.OkAction;
import org.pac4j.core.http.ajax.DefaultAjaxRequestResolver;
import org.pac4j.core.redirect.RedirectionActionBuilder;
import org.pac4j.core.util.CommonHelper;
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
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class Pac4jAjaxRequestResolver extends DefaultAjaxRequestResolver {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	private JwtPayloadRepository jwtPayloadRepository;
    private UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
	@Override
	public HttpAction buildAjaxResponse(final WebContext context, 
            final RedirectionActionBuilder redirectionActionBuilder) {
        
    	CommonHelper.assertNotNull("jwtPayloadRepository", jwtPayloadRepository);
    	CommonHelper.assertNotNull("userDetailsService", userDetailsService);
    	CommonHelper.assertNotNull("userDetailsChecker", userDetailsChecker);
    	
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

        return new OkAction(tokenString);
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
