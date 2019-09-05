package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;


@ConfigurationProperties(prefix = SecurityPac4jProperties.PREFIX)
@Getter
@Setter
public class SecurityPac4jProperties {

	public static final String PREFIX = "spring.security.pac4j";
    
	/** Whether Enable Pac4j Authentication. */
	private boolean enabled = false;

	private boolean localLogout;

	private boolean destroySession;

	private boolean centralLogout;
	
}
