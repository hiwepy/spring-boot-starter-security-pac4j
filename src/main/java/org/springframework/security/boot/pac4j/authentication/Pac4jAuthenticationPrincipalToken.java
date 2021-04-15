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
package org.springframework.security.boot.pac4j.authentication;

import java.util.Collection;

import org.springframework.security.boot.biz.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class Pac4jAuthenticationPrincipalToken extends AbstractAuthenticationToken {
	
	// ~ Constructors
	// ===================================================================================================

	/**
	 * This constructor can be safely used by any code that wishes to create a
	 * <code>Pac4jAuthenticationPrincipalToken</code>, as the {@link #isAuthenticated()}
	 * will return <code>false</code>.
	 * @param principal the principal
	 * @param credentials the credentials
	 */
	public Pac4jAuthenticationPrincipalToken(Object principal, Object credentials) {
		super(principal, credentials, null);
		setAuthenticated(false);
	}

	/**
	 * This constructor should only be used by <code>AuthenticationManager</code> or
	 * <code>AuthenticationProvider</code> implementations that are satisfied with
	 * producing a trusted (i.e. {@link #isAuthenticated()} = <code>true</code>)
	 * authentication token.
	 *
	 * @param principal the principal
	 * @param credentials the credentials
	 * @param authorities the authorities
	 */
	public Pac4jAuthenticationPrincipalToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(principal,  credentials, authorities);
	}
 
}