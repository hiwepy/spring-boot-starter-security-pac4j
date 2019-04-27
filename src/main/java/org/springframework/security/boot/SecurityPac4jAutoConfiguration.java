package org.springframework.security.boot;

import org.pac4j.core.config.Config;
import org.pac4j.springframework.security.web.Pac4jEntryPoint;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

// http://blog.csdn.net/change_on/article/details/76302161
@Configuration
@AutoConfigureBefore( name = {
	"org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebAutoConfiguration"  // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityPac4jProperties.class })
@EnableWebSecurity
public class SecurityPac4jAutoConfiguration extends WebSecurityConfigurerAdapter {
  
    @Bean
	@ConditionalOnMissingBean
    public Pac4jEntryPoint pac4jEntryPoint(Config config, final String clientName){
		return new Pac4jEntryPoint(config, clientName);
	}

}
