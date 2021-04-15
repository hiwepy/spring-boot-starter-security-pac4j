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

import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.UserProfile;

/**
 * Pac4j authentication interface.
 *
 * @author Jerome Leleu
 * @since 2.0.0
 */
public interface Pac4jAuthentication {

    /**
     * Get the main profile of the authenticated user.
     *
     * @return the main profile
     */
    default UserProfile getProfile() {
        return ProfileHelper.flatIntoOneProfile(getProfiles()).get();
    }

    /**
     * Get all the profiles of the authenticated user.
     *
     * @return the list of profiles
     */
    List<UserProfile> getProfiles();
    
}
