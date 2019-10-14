package org.springframework.security.boot;

import org.pac4j.core.config.Config;
import org.pac4j.spring.boot.Pac4jLogoutProperties;
import org.pac4j.spring.boot.Pac4jProperties;
import org.pac4j.spring.boot.utils.Pac4jUrlUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticatedSecurityFilter;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticationCallbackFilter;
import org.springframework.security.boot.pac4j.authentication.logout.Pac4jLogoutHandler;
import org.springframework.security.boot.pac4j.authorizer.Pac4jEntryPoint;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityPac4jAuthcProperties.class,
		SecurityPac4jCallbackProperties.class, Pac4jLogoutProperties.class, ServerProperties.class })
public class SecurityPac4jFilterAutoConfiguration {

	/**
	 * 账号注销处理器 ：处理账号注销
	 */
	@Bean
	public Pac4jLogoutHandler pac4jLogoutHandler(Config config, Pac4jProperties pac4jProperties,
			Pac4jLogoutProperties logoutProperties, ServerProperties serverProperties){
		
		Pac4jLogoutHandler logoutHandler = new Pac4jLogoutHandler();
        
		// Whether the centralLogout must be performed（是否注销统一身份认证）
		logoutHandler.setCentralLogout(logoutProperties.isCentralLogout());
		// Security Configuration
		logoutHandler.setConfig(config);
        // Default logourl url
		String logoutUrl = Pac4jUrlUtils.constructCallbackUrl(serverProperties.getServlet().getContextPath(), pac4jProperties.getLogoutUrl());
		logoutHandler.setDefaultUrl(logoutUrl);
        // Whether the Session must be destroyed（是否销毁Session）
		logoutHandler.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
		logoutHandler.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
		logoutHandler.setLogoutUrlPattern(logoutProperties.getLogoutUrlPattern());
		
	    return logoutHandler;
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityPac4jAuthcProperties.class,
		SecurityPac4jCallbackProperties.class, Pac4jLogoutProperties.class, Pac4jProperties.class, ServerProperties.class })
    @Order(110)
	static class Pac4jWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

		private final AuthenticationManager authenticationManager;
		private final Config config;
		private final Pac4jEntryPoint pac4jEntryPoint;

		private final Pac4jProperties pac4jProperties;
		private final SecurityPac4jAuthcProperties pac4jAuthcProperties;
		private final SecurityPac4jCallbackProperties pac4jCallbackProperties;
		private final ServerProperties serverProperties;
		
		public Pac4jWebSecurityConfigurationAdapter(
				SecurityBizProperties bizProperties,
				SecurityPac4jAuthcProperties pac4jAuthcProperties,
				SecurityPac4jCallbackProperties pac4jCallbackProperties,
				Pac4jProperties pac4jProperties,
				ServerProperties serverProperties,
				
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<Config> configProvider,
				ObjectProvider<Pac4jEntryPoint> pac4jEntryPointProvider) {
			
			this.pac4jProperties = pac4jProperties;
			this.pac4jAuthcProperties = pac4jAuthcProperties;
			this.pac4jCallbackProperties = pac4jCallbackProperties;
			this.serverProperties = serverProperties;
			
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.config = configProvider.getIfAvailable();
			this.pac4jEntryPoint = pac4jEntryPointProvider.getIfAvailable();
		}

		/**
		 * 权限控制过滤器 ：实现权限认证
		 */
		@Bean
		public Pac4jPreAuthenticatedSecurityFilter pac4jSecurityFilter(){
			
			Pac4jPreAuthenticatedSecurityFilter securityFilter = new Pac4jPreAuthenticatedSecurityFilter();  
			
			securityFilter.setAuthenticationManager(authenticationManager);
			if (StringUtils.hasText(pac4jAuthcProperties.getPathPattern())) {
				securityFilter.setFilterProcessesUrl(pac4jAuthcProperties.getPathPattern());
			}
			
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
		    
			callbackFilter.setAuthenticationManager(authenticationManager);
			if (StringUtils.hasText(pac4jCallbackProperties.getPathPattern())) {
				callbackFilter.setFilterProcessesUrl(pac4jCallbackProperties.getPathPattern());
			}
			
		    // Security Configuration
	        callbackFilter.setConfig(config);
	        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
	        String callbackUrl = Pac4jUrlUtils.constructCallbackUrl(serverProperties.getServlet().getContextPath(), pac4jProperties.getCallbackUrl());
	        callbackFilter.setDefaultUrl( callbackUrl );
	        // Whether multiple profiles should be kept
	        callbackFilter.setMultiProfile(pac4jProperties.isMultiProfile());
	        
		    return callbackFilter;
		}
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.exceptionHandling().authenticationEntryPoint(pac4jEntryPoint)
				.and()
				.addFilterBefore(pac4jSecurityFilter(), BasicAuthenticationFilter.class)
				.addFilterBefore(pac4jCallbackFilter(), BasicAuthenticationFilter.class);
		}
		
		@Override
   	    public void configure(WebSecurity web) throws Exception {
   	    	web.ignoring()
   	    		.antMatchers(pac4jProperties.getCallbackUrl());
   	    }

	}

}
