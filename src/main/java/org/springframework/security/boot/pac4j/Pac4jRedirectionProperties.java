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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * TODO
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class Pac4jRedirectionProperties {

	/** Header Pattern */
	private Map<String, String> headerPattern = new HashMap<String, String>();
	
	/** Parameter Pattern */
	private Map<String, String> paramPattern = new HashMap<String, String>();
	
	/** Path Pattern */
	private String pathPattern;

	private String redirectUrl; 

	/**
	 * Define on which error URL the user will be redirected in case of an exception.
	 */
	private String errorUrl;

	private String targetUrlParameter = "target";
	
	private String defaultTargetUrl = "/";
	
	private boolean alwaysUseDefaultTargetUrl = false;
	
	private boolean useReferer = false;
	
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
	
	public boolean isUseReferer() {
		return useReferer;
	}

	public void setUseReferer(boolean useReferer) {
		this.useReferer = useReferer;
	}
	
	
}
