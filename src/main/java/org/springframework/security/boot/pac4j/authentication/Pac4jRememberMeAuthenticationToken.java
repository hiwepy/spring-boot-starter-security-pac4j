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


import java.util.List;

import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.UserProfile;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.boot.utils.SpringSecurityHelper;

/**
 * Pac4j authentication token in case of remember-me.
 *
 * @author Jerome Leleu
 * @since 2.0.0
 */
@SuppressWarnings("serial")
public class Pac4jRememberMeAuthenticationToken extends RememberMeAuthenticationToken implements Pac4jAuthentication {

    private final List<UserProfile> profiles;

    public Pac4jRememberMeAuthenticationToken(final List<UserProfile> profiles) {
        super("rme", ProfileHelper.flatIntoOneProfile(profiles).get(), SpringSecurityHelper.buildAuthorities(profiles));
        this.profiles = profiles;
        setAuthenticated(true);
    }

    @Override
    public String getName() {
        return ((CommonProfile) getPrincipal()).getId();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        final Pac4jRememberMeAuthenticationToken that = (Pac4jRememberMeAuthenticationToken) o;

        return profiles != null ? profiles.equals(that.profiles) : that.profiles == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (profiles != null ? profiles.hashCode() : 0);
        return result;
    }

    @Override
    public List<UserProfile> getProfiles() {
        return this.profiles;
    }
    
}
