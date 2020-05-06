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

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.util.CommonHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */

public class DefaultPac4jRedirectionUrlParser implements Pac4jRedirectionUrlParser {
	
	private static final Logger logger = LoggerFactory.getLogger(DefaultPac4jRedirectionUrlParser.class);
	private AntPathMatcher matcher = new AntPathMatcher();
	private List<Pac4jRedirectionProperties> redirects;
	
	public DefaultPac4jRedirectionUrlParser(List<Pac4jRedirectionProperties> redirects) {
		this.redirects = redirects;
	}
	
	@Override
	public Optional<String> errorUrl(WebContext context) {
		if(CollectionUtils.isEmpty(redirects)) {
			return Optional.empty();
		}
		for (Pac4jRedirectionProperties properties : redirects) {
			if(!StringUtils.hasText(properties.getErrorUrl())) {
				continue;
			}
			if (StringUtils.hasText(properties.getPathPattern())) {
				logger.debug("请求路径匹配规则：{}", properties.getPathPattern());
				if(matcher.match(properties.getPathPattern(), context.getPath())) {
					logger.debug("成功匹配上下文：{}", context.getPath());
					return Optional.of(properties.getErrorUrl());
				}
				if(matcher.match(properties.getPathPattern(), context.getFullRequestURL())) {
					logger.debug("成功匹配全路径：{}", context.getPath());
					return Optional.of(properties.getErrorUrl());
				}
			}
			Map<String, String> headerPattern = properties.getHeaderPattern();
			if(!CollectionUtils.isEmpty(headerPattern)) {
				logger.debug("请求头匹配规则：{}", JSONObject.toJSONString(headerPattern));
				for (String header : headerPattern.keySet()) {
					Optional<String> headerOptional =  context.getRequestHeader(header);
					if(headerOptional.isPresent() && matcher.match(headerOptional.get(), headerPattern.get(header))) {
						logger.debug("匹配规则 {} 成功匹配请求头：{} = {}", headerPattern.get(header), header, headerOptional.get());
						return Optional.of(properties.getErrorUrl());
					}
				}
			}
			Map<String, String> paramPattern = properties.getParamPattern();
			if(!CollectionUtils.isEmpty(paramPattern)) {
				logger.debug("请参数匹配规则：{}", JSONObject.toJSONString(paramPattern));
				for (String param : paramPattern.keySet()) {
					Optional<String> paramOptional =  context.getRequestParameter(param);
					if(paramOptional.isPresent() && matcher.match(paramOptional.get(), paramPattern.get(param))) {
						logger.debug("匹配规则 {} 成功匹配请求头：{} = {}", paramPattern.get(param), param, paramOptional.get());
						return Optional.of(properties.getErrorUrl());
					}
				}
			}
		}
		return Optional.empty();
	}
	
	@Override
	public Optional<String> redirectUrl(WebContext context, Authentication authentication) {
		if(CollectionUtils.isEmpty(redirects)) {
			return Optional.empty();
		}
		for (Pac4jRedirectionProperties properties : redirects) {

			if(!StringUtils.hasText(properties.getRedirectUrl())) {
				continue;
			}
			
			if (StringUtils.hasText(properties.getPathPattern())) {
				logger.debug("请求路径匹配规则：{}", properties.getPathPattern());
				if(matcher.match(properties.getPathPattern(), context.getPath())) {
					logger.debug("成功匹配上下文：{}", context.getPath());
					return this.finalRedirectUrl(context, properties);
				}
				if(matcher.match(properties.getPathPattern(), context.getFullRequestURL())) {
					logger.debug("成功匹配全路径：{}", context.getPath());
					return this.finalRedirectUrl(context, properties);
				}
			}
			Map<String, String> headerPattern = properties.getHeaderPattern();
			if(!CollectionUtils.isEmpty(headerPattern)) {
				logger.debug("请求头匹配规则：{}", JSONObject.toJSONString(headerPattern));
				for (String header : headerPattern.keySet()) {
					Optional<String> headerOptional =  context.getRequestHeader(header);
					if(headerOptional.isPresent() && matcher.match(headerOptional.get(), headerPattern.get(header))) {
						logger.debug("匹配规则 {} 成功匹配请求头：{} = {}", headerPattern.get(header), header, headerOptional.get());
						return this.finalRedirectUrl(context, properties);
					}
				}
			}
			Map<String, String> paramPattern = properties.getParamPattern();
			if(!CollectionUtils.isEmpty(paramPattern)) {
				logger.debug("请参数匹配规则：{}", JSONObject.toJSONString(paramPattern));
				for (String param : paramPattern.keySet()) {
					Optional<String> paramOptional =  context.getRequestParameter(param);
					if(paramOptional.isPresent() && matcher.match(paramOptional.get(), paramPattern.get(param))) {
						logger.debug("匹配规则 {} 成功匹配请求头：{} = {}", paramPattern.get(param), param, paramOptional.get());
						return this.finalRedirectUrl(context, properties);
					}
				}
			}
		}
		return Optional.empty();
	}
	
	protected Optional<String> finalRedirectUrl(WebContext context, Pac4jRedirectionProperties properties) {
		
		// 获取上下文
    	JEEContext jeeContext = (JEEContext) context;
    	
    	String redirectionUrl = CommonHelper.addParameter(properties.getRedirectUrl(), "target", this.determineTargetUrl(jeeContext, properties));
        
        return Optional.of(redirectionUrl);
	}


	/**
	 * Builds the target URL according to the logic defined in the main class Javadoc.
	 */
	protected String determineTargetUrl(WebContext context, Pac4jRedirectionProperties properties) {
		if (properties.isAlwaysUseDefaultTargetUrl()) {
			return properties.getDefaultTargetUrl();
		}

		// Check for the parameter and use that if available
		String targetUrl = null;

		if (properties.getTargetUrlParameter() != null) {
			targetUrl = context.getRequestParameter(properties.getTargetUrlParameter()).orElse("");
			if (StringUtils.hasText(targetUrl)) {
				logger.debug("Found targetUrlParameter in request: " + targetUrl);
				try {
					return URLDecoder.decode(targetUrl, StandardCharsets.UTF_8.name());
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				return targetUrl;
			}
		}

		if (properties.isUseReferer() && !StringUtils.hasText(targetUrl)) {
			targetUrl = context.getRequestHeader("Referer").orElse("");
			logger.debug("Using Referer header: " + targetUrl);
		}

		if (!StringUtils.hasText(targetUrl)) {
			targetUrl = properties.getDefaultTargetUrl();
			logger.debug("Using default Url: " + targetUrl);
		}

		return targetUrl;
	}

}
