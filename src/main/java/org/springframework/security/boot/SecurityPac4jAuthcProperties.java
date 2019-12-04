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
package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityPac4jAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityPac4jAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.pac4j.authc";

	/** Authorization Path Pattern */
	private String pathPattern = "/login/pac4j";

	/**
	 * Whether Enable Front-end Authorization Proxy.
	 */
	private boolean authzProxy = false;

	/**
	 * The location of the front-end server login URL, i.e.
	 * http://localhost:8080/#/client?target=/portal
	 * http://localhost:8080/#/client?client_name=cas&target=/portal
	 */
	private String authzProxyUrl;

	/**
	 * Define on which error URL the user will be redirected in case of an exception.
	 */
	private String errorUrl;
	
}
