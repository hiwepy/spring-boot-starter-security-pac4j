package org.springframework.security.boot;

import org.pac4j.core.config.Config;
import org.pac4j.spring.boot.Pac4jLogoutProperties;
import org.pac4j.spring.boot.Pac4jProperties;
import org.pac4j.spring.boot.ext.Pac4jPathBuilder;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticatedSecurityFilter;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticationCallbackFilter;
import org.springframework.security.boot.pac4j.authentication.logout.Pac4jLogoutHandler;
import org.springframework.security.boot.pac4j.authorizer.Pac4jEntryPoint;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
//@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityPac4jProperties.class, Pac4jLogoutProperties.class, ServerProperties.class })
public class SecurityPac4jFilterAutoConfiguration {

	/**
	 * 账号注销处理器 ：处理账号注销
	 */
	@Bean
	public Pac4jLogoutHandler pac4jLogoutHandler(Config config, Pac4jPathBuilder pathBuilder, Pac4jLogoutProperties logoutProperties, ServerProperties serverProperties){
		
		Pac4jLogoutHandler logoutHandler = new Pac4jLogoutHandler();
        
		// Whether the centralLogout must be performed（是否注销统一身份认证）
		logoutHandler.setCentralLogout(logoutProperties.isCentralLogout());
		// Security Configuration
		logoutHandler.setConfig(config);
        // Default logourl url
		logoutHandler.setDefaultUrl( pathBuilder.getLogoutURL(serverProperties.getServlet().getContextPath()) );
        // Whether the Session must be destroyed（是否销毁Session）
		logoutHandler.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
		logoutHandler.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
		logoutHandler.setLogoutUrlPattern(logoutProperties.getLogoutUrlPattern());
        
	    return logoutHandler;
	}

	
	@Configuration
	@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityBizProperties.class })
	static class Pac4jWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

	    private final Config config;
		private final Pac4jPathBuilder pathBuilder;
		private final Pac4jProperties pac4jProperties;
		private final ServerProperties serverProperties;
	    
		public Pac4jWebSecurityConfigurationAdapter(
				Pac4jProperties pac4jProperties,
				ServerProperties serverProperties,
				ObjectProvider<Config> configProvider,
   				ObjectProvider<Pac4jPathBuilder> pathBuilderProvider) {
			
			this.pac4jProperties = pac4jProperties;
			this.serverProperties = serverProperties;
			this.config = configProvider.getIfAvailable();
			this.pathBuilder = pathBuilderProvider.getIfAvailable();
		}

		/**
		 * 权限控制过滤器 ：实现权限认证
		 */
		@Bean
		public Pac4jPreAuthenticatedSecurityFilter pac4jSecurityFilter(){
			
			Pac4jPreAuthenticatedSecurityFilter securityFilter = new Pac4jPreAuthenticatedSecurityFilter();  
			
			// List of authorizers
			securityFilter.setAuthorizers(pac4jProperties.getAuthorizers());
			// List of clients for authentication
			securityFilter.setClients(pac4jProperties.getClients());
			// Security configuration
			securityFilter.setConfig(config);
			securityFilter.setMatchers(pac4jProperties.getMatchers());
			// Whether multiple profiles should be kept
			securityFilter.setMultiProfile(pac4jProperties.isMultiProfile());
			
		    return securityFilter;
		}
		
		/**
		 * 回调过滤器 ：处理登录后的回调访问
		 */
		@Bean
		public Pac4jPreAuthenticationCallbackFilter pac4jCallbackFilter(){
			
			Pac4jPreAuthenticationCallbackFilter callbackFilter = new Pac4jPreAuthenticationCallbackFilter();
		    
		    // Security Configuration
	        callbackFilter.setConfig(config);
	        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
	        callbackFilter.setDefaultUrl( pathBuilder.getLoginURL(serverProperties.getServlet().getContextPath()) );
	        // Whether multiple profiles should be kept
	        callbackFilter.setMultiProfile(pac4jProperties.isMultiProfile());
	        
		    return callbackFilter;
		}
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(new Pac4jEntryPoint(config, "CasClient", null))
				.and()
				.addFilterBefore(pac4jSecurityFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(pac4jCallbackFilter(), BasicAuthenticationFilter.class);
		}

	}

}
