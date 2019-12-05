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

public class DefaultPac4jCallbackUrlParser implements Pac4jCallbackUrlParser {

	private AntPathMatcher matcher = new AntPathMatcher();
	private List<Pac4jCallbackProperties> redirects;
	
	public DefaultPac4jCallbackUrlParser(List<Pac4jCallbackProperties> redirects) {
		this.redirects = redirects;
	}
	
	@Override
	public Optional<String> parser(WebContext context) {
		if(CollectionUtils.isEmpty(redirects)) {
			return Optional.empty();
		}
		for (Pac4jCallbackProperties properties : redirects) {
			if(matcher.match(properties.getPathPattern(), context.getPath()) || matcher.match(properties.getPathPattern(), context.getFullRequestURL())) {
				return Optional.of(properties.getCallbackUrl());
			}
			Map<String, String> headerPattern = properties.getHeaderPattern();
			if(!CollectionUtils.isEmpty(headerPattern)) {
				for (String header : headerPattern.keySet()) {
					Optional<String> headerOptional =  context.getRequestHeader(header);
					if(headerOptional.isPresent() && matcher.match(headerOptional.get(), headerPattern.get(header))) {
						return Optional.of(properties.getCallbackUrl());
					}
				}
			}
			Map<String, String> paramPattern = properties.getParamPattern();
			if(!CollectionUtils.isEmpty(paramPattern)) {
				for (String param : paramPattern.keySet()) {
					Optional<String> paramOptional =  context.getRequestParameter(param);
					if(paramOptional.isPresent() && matcher.match(paramOptional.get(), headerPattern.get(param))) {
						return Optional.of(properties.getCallbackUrl());
					}
				}
			}
		}
		return Optional.empty();
	}
	
	@Override
	public Optional<String> parser(WebContext context, Authentication authentication) {
		return this.parser(context);
	}

}
