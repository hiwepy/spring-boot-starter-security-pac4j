package org.springframework.security.boot;

import org.pac4j.core.config.Config;
import org.pac4j.spring.boot.Pac4jProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.boot.pac4j.authorizer.Pac4jEntryPointExt;

// http://blog.csdn.net/change_on/article/details/76302161
@Configuration
@AutoConfigureBefore(SecurityAutoConfiguration.class)
@ConditionalOnClass(DefaultAuthenticationEventPublisher.class)
@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ Pac4jProperties.class })
public class SecurityPac4jAutoConfiguration {
  
	@Autowired
	private Pac4jProperties pac4jProperties;
	
    @Bean
	@ConditionalOnMissingBean
    public Pac4jEntryPointExt pac4jEntryPoint(Config config){
		return new Pac4jEntryPointExt(config, pac4jProperties.getClientName(), pac4jProperties.getClientParameterName());
	}

}
