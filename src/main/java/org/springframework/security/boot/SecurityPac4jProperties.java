package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityPac4jProperties.PREFIX)
public class SecurityPac4jProperties {

	public static final String PREFIX = "spring.security.pac4j";
    
	/** Whether Enable Pac4j Authentication. */
	private boolean enabled = false;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	
}
