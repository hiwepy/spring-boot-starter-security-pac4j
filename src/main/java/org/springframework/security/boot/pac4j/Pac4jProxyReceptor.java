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

import static org.pac4j.core.util.CommonHelper.toNiceString;

import java.util.Optional;

import org.pac4j.core.client.IndirectClient;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.exception.http.FoundAction;
import org.pac4j.core.exception.http.OkAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pac4jProxyReceptor extends IndirectClient {

    public static final String PARAM_PROXY_TARGET = "target";

    private static final Logger logger = LoggerFactory.getLogger(Pac4jProxyReceptor.class);
    
    @Override
    protected void internalInit() {
    	
        defaultCredentialsExtractor((context, sessionStore) -> {
        	
            final Optional<String> proxyTarget = context.getRequestParameter(PARAM_PROXY_TARGET);
            logger.debug("proxyTarget: {}", proxyTarget);

            if (!proxyTarget.isPresent()) {
                logger.warn("Missing proxyGrantingTicket or proxyGrantingTicketIou -> returns ok");
                throw new OkAction("");
            }

            throw new OkAction(proxyTarget.get());
        });
        
        defaultRedirectionActionBuilder((context, sessionStore) -> {
        	//new Pac4jRedirectionActionBuilder()
                 
        	return Optional.of(new FoundAction(callbackUrl));
        });
        
        defaultAuthenticator((credentials, context, sessionStore) -> { throw new TechnicalException("Not supported by the CAS proxy receptor"); });
    }

    @Override
    public String toString() {
        return toNiceString(this.getClass(), "callbackUrl", this.callbackUrl);
    }

}
