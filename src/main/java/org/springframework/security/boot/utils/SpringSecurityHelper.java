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


import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import org.pac4j.core.authorization.authorizer.Authorizer;
import org.pac4j.core.authorization.authorizer.IsFullyAuthenticatedAuthorizer;
import org.pac4j.core.authorization.authorizer.IsRememberedAuthorizer;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.UserProfile;
import org.springframework.security.boot.pac4j.authentication.Pac4jAuthenticationToken;
import org.springframework.security.boot.pac4j.authentication.Pac4jRememberMeAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Helper for Spring Security.
 *
 * @author Jerome Leleu
 * @since 2.0.0
 */
public final class SpringSecurityHelper {

    private final static Authorizer IS_REMEMBERED_AUTHORIZER = new IsRememberedAuthorizer();

    private final static Authorizer IS_FULLY_AUTHENTICATED_AUTHORIZER = new IsFullyAuthenticatedAuthorizer();

    /**
     * Build a list of authorities from a list of profiles.
     *
     * @param profiles a map of profiles
     * @return a list of authorities
     */
    public static List<GrantedAuthority> buildAuthorities(final List<UserProfile> profiles) {
        final List<GrantedAuthority> authorities = new ArrayList<>();
        for (final UserProfile profile : profiles) {
            final Set<String> roles = profile.getRoles();
            for (final String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
        }
        return authorities;
    }
    /**
     * Populate the authenticated user profiles in the Spring Security context.
     *
     * @param profiles the linked hashmap of profiles
     */
    public static void populateAuthentication(WebContext context, SessionStore sessionStore, final LinkedHashMap<String, UserProfile> profiles) {
        if (profiles != null && profiles.size() > 0) {
            final List<UserProfile> listProfiles = ProfileHelper.flatIntoAProfileList(profiles);
            try {
                if (IS_FULLY_AUTHENTICATED_AUTHORIZER.isAuthorized(context, sessionStore, listProfiles)) {
                    SecurityContextHolder.getContext().setAuthentication(new Pac4jAuthenticationToken(listProfiles));
                } else if (IS_REMEMBERED_AUTHORIZER.isAuthorized(context, sessionStore, listProfiles)) {
                    SecurityContextHolder.getContext().setAuthentication(new Pac4jRememberMeAuthenticationToken(listProfiles));
                }
            } catch (final HttpAction e) {
                throw new TechnicalException(e);
            }
        }
    }
}
