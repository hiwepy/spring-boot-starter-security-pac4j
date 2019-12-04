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
import java.util.Map;
import java.util.Optional;

import org.pac4j.core.context.WebContext;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;

/**
 * TODO
 * @author 		： <a href="https://github.com/vindell">wandl</a>
 */

public class DefaultPac4jRedirectionUrlParser implements Pac4jRedirectionUrlParser {

	private AntPathMatcher matcher = new AntPathMatcher();
	private List<Pac4jRedirectionProperties> redirects;
	
	public DefaultPac4jRedirectionUrlParser(List<Pac4jRedirectionProperties> redirects) {
		this.redirects = redirects;
	}
	
	@Override
	public Optional<String> parser(WebContext context, Authentication authentication) {
		if(CollectionUtils.isEmpty(redirects)) {
			return Optional.empty();
		}
		for (Pac4jRedirectionProperties properties : redirects) {
			if(matcher.match(properties.getPathPattern(), context.getPath()) || matcher.match(properties.getPathPattern(), context.getFullRequestURL())) {
				return Optional.of(properties.getRedirectUrl());
			}
			Map<String, String> headerPattern = properties.getHeaderPattern();
			if(!CollectionUtils.isEmpty(headerPattern)) {
				// String
				for (String header : headerPattern.keySet()) {
					Optional<String> headerOptional =  context.getRequestHeader(header);
					if(headerOptional.isPresent() && matcher.match(headerOptional.get(), headerPattern.get(header))) {
						return Optional.of(properties.getRedirectUrl());
					}
				}
			}
		}
		return Optional.empty();
	}

}
