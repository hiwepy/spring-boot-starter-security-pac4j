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
package org.springframework.security.boot.utils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.pac4j.core.context.JEEContext;
import org.pac4j.core.profile.UserProfile;
import org.springframework.security.boot.pac4j.authentication.Pac4jAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.util.WebUtils;

/**
 * TODO
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class ProfileUtils {

	public static SecurityContext getSecurityContext() {
		return SecurityContextHolder.getContext();
	}

	public static Authentication getAuthentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	public static <T> T getPrincipal(Class<T> clazz) {
		Object principal = getAuthentication().getPrincipal();
		// 自身类.class.isAssignableFrom(自身类或子类.class)
		if (clazz.isAssignableFrom(principal.getClass())) {
			return (T) principal;
		}
		return null;
	}

	public static Object getPrincipal() {
		return getAuthentication().getPrincipal();
	}

	public static boolean isAuthenticated() {
		return getAuthentication().isAuthenticated();
	}

	public static ServletRequestAttributes getRequestAttributes() {
		return (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
	}
	
	public static HttpServletRequest getRequest() {
		return getRequestAttributes().getRequest();
	}
	
	public static HttpServletResponse getResponse() {
		return ((ServletWebRequest) RequestContextHolder.getRequestAttributes()).getResponse();
	}
	
	public static HttpSession getSession(boolean create) {
		return getRequest().getSession(create);
	}

	public static JEEContext getJEEContext() {
		return new JEEContext(getRequest(), getResponse());
	}
	
	public static JEEContext getJEEContext(ServletRequest request, ServletResponse response) {
		return new JEEContext(WebUtils.getNativeRequest(request, HttpServletRequest.class),
				WebUtils.getNativeResponse(response, HttpServletResponse.class));
	}

	public static UserProfile getProfile() {

		Authentication auth = getAuthentication();
		if (auth != null && auth instanceof Pac4jAuthentication) {
			Pac4jAuthentication token = (Pac4jAuthentication) auth;
			return token.getProfile();
		}
		return null;

	}
	
	public static <T extends UserProfile> T getProfile(Class<T> clazz) {
		Authentication auth = getAuthentication();
		if (auth != null && auth instanceof Pac4jAuthentication) {
			Pac4jAuthentication token = (Pac4jAuthentication) auth;
			UserProfile profile = token.getProfile();
			// 自身类.class.isAssignableFrom(自身类或子类.class)
			if (clazz.isAssignableFrom(profile.getClass())) {
				return (T) profile;
			}
			return null;
		}
		return null;
	}

}
