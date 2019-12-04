package org.springframework.security.boot;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.pac4j.Pac4jRedirectionProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;


@ConfigurationProperties(prefix = SecurityPac4jProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityPac4jProperties {

	public static final String PREFIX = "spring.security.pac4j";
    
	/** Whether Enable Pac4j Authentication. */
	private boolean enabled = false;

	private List<Pac4jRedirectionProperties> redirects;
	
}
