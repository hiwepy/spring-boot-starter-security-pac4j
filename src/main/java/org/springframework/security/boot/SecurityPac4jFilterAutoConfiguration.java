package org.springframework.security.boot;

import java.util.stream.Collectors;

import org.pac4j.core.config.Config;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.engine.LogoutLogic;
import org.pac4j.spring.boot.Pac4jAutoConfiguration;
import org.pac4j.spring.boot.Pac4jLogoutProperties;
import org.pac4j.spring.boot.Pac4jProperties;
import org.pac4j.spring.boot.utils.Pac4jUrlUtils;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.LogoutFilter;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.pac4j.DefaultPac4jCallbackUrlParser;
import org.springframework.security.boot.pac4j.DefaultPac4jRedirectionUrlParser;
import org.springframework.security.boot.pac4j.Pac4jCallbackUrlParser;
import org.springframework.security.boot.pac4j.Pac4jRedirectionUrlParser;
import org.springframework.security.boot.pac4j.authentication.logout.Pac4jLogoutHandler;
import org.springframework.security.boot.pac4j.authorizer.Pac4jExtEntryPoint;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@AutoConfigureAfter(Pac4jAutoConfiguration.class)
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityPac4jAuthcProperties.class,
		SecurityPac4jCallbackProperties.class, Pac4jLogoutProperties.class, ServerProperties.class })
public class SecurityPac4jFilterAutoConfiguration {

	@Bean
	public Pac4jLogoutHandler pac4jLogoutHandler(Config config, LogoutLogic<Object, JEEContext> logoutLogic,
			Pac4jLogoutProperties logoutProperties){
		
		Pac4jLogoutHandler logoutHandler = new Pac4jLogoutHandler(config, logoutLogic);
        
		// Whether the centralLogout must be performed（是否注销统一身份认证）
		logoutHandler.setCentralLogout(logoutProperties.isCentralLogout());
		// Security Configuration
		logoutHandler.setConfig(config);
        // Default logourl url
		logoutHandler.setDefaultUrl(logoutProperties.getDefaultUrl());
        // Whether the Session must be destroyed（是否销毁Session）
		logoutHandler.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
		logoutHandler.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配注销请求操作）
		logoutHandler.setLogoutUrlPattern(logoutProperties.getPathPattern());
		
	    return logoutHandler;
	}
	
	@Bean
	@ConditionalOnMissingBean
	public Pac4jRedirectionUrlParser redirectionUrlParser(SecurityPac4jAuthcProperties authcProperties) {
		return new DefaultPac4jRedirectionUrlParser(authcProperties.getRedirects());
	}
	
	@Bean
	@ConditionalOnMissingBean
	public Pac4jCallbackUrlParser callbackUrlParser(SecurityPac4jCallbackProperties callbackProperties) {
		return new DefaultPac4jCallbackUrlParser(callbackProperties.getRedirects());
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityPac4jAuthcProperties.class,
		SecurityPac4jCallbackProperties.class, Pac4jLogoutProperties.class, Pac4jProperties.class, ServerProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 20)
	static class Pac4jWebSecurityConfigurationAdapter extends WebSecurityBizConfigurerAdapter {

		private final Pac4jProperties pac4jProperties;
		private final Pac4jLogoutProperties pac4jLogoutProperties;
		private final SecurityPac4jAuthcProperties authcProperties;
		private final SecurityPac4jCallbackProperties callbackProperties;
		
	    private final Config pac4jConfig;
	    private final LogoutLogic<Object, JEEContext> logoutLogic;
	    private final Pac4jExtEntryPoint authenticationEntryPoint;
	    private final LocaleContextFilter localeContextFilter;
    	
		public Pac4jWebSecurityConfigurationAdapter(
				
				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
				SecurityPac4jAuthcProperties authcProperties,
				SecurityPac4jCallbackProperties callbackProperties,
				Pac4jProperties pac4jProperties,
				Pac4jLogoutProperties pac4jLogoutProperties,
				
				ObjectProvider<Config> pac4jConfigProvider,
				ObjectProvider<LogoutLogic<Object, JEEContext>> logoutLogicProvider,
				ObjectProvider<Pac4jExtEntryPoint> authenticationEntryPointProvider,
				
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider
			) {
			
			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
			
			this.pac4jProperties = pac4jProperties;
			this.authcProperties = authcProperties;
			this.callbackProperties = callbackProperties;
			this.pac4jLogoutProperties = pac4jLogoutProperties;
			
			
			this.pac4jConfig = pac4jConfigProvider.getIfAvailable();
			this.logoutLogic = logoutLogicProvider.getIfAvailable();
   			
			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable(); 
   			
		}

		
		/*
		 * 权限控制过滤器 ：实现权限认证
		 */
		public SecurityFilter pac4jSecurityFilter() throws Exception {
			
			SecurityFilter securityFilter = new SecurityFilter();  
			
			// List of authorizers
			securityFilter.setAuthorizers(pac4jProperties.getAuthorizers());
			// List of clients for authentication
			securityFilter.setClients(pac4jProperties.getClients());
			// Security configuration
			securityFilter.setConfig(pac4jConfig);
			//securityFilter.setErrorUrl(authcProperties.getErrorUrl());
			securityFilter.setMatchers(pac4jProperties.getMatchers());
			// Whether multiple profiles should be kept
			securityFilter.setMultiProfile(pac4jProperties.isMultiProfile());
			
		    return securityFilter;
		}
		
		/*
		 * 回调过滤器 ：处理登录后的回调访问
		 */
		public CallbackFilter pac4jCallbackFilter() throws Exception {
			
			CallbackFilter callbackFilter = new CallbackFilter();
			
			// 
			callbackFilter.setApplicationContext(this.getApplicationContext());
		    // Security Configuration
	        callbackFilter.setConfig(pac4jConfig);
	        callbackFilter.setDefaultClient(pac4jProperties.getDefaultClientName());

	        if(authcProperties.isAuthzProxy()) {
	        	callbackFilter.setDefaultUrl( authcProperties.getAuthzProxyUrl() );
	        } else {
	        	// Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
		        String callbackUrl = Pac4jUrlUtils.constructRedirectUrl(callbackProperties.getDefaultUrl(), pac4jProperties.getClientParameterName(), pac4jProperties.getDefaultClientName());
		        callbackFilter.setDefaultUrl( callbackUrl );
			}
	        
	        // Whether multiple profiles should be kept
	        callbackFilter.setMultiProfile(callbackProperties.isMultiProfile());
	        callbackFilter.setRenewSession(callbackProperties.isRenewSession());
	        callbackFilter.setSaveInSession(callbackProperties.isSaveInSession());
	        
		    return callbackFilter;
		}
		
		/*
		 * 登出过滤器 ：处理登录后的回调访问
		 */
		public LogoutFilter pac4jLogoutFilter() throws Exception {
			
			LogoutFilter logoutFilter = new LogoutFilter();
			
			logoutFilter.setCentralLogout(pac4jLogoutProperties.isCentralLogout());
		    // Security Configuration
	        logoutFilter.setConfig(pac4jConfig);

	        if(authcProperties.isAuthzProxy()) {
	        	logoutFilter.setDefaultUrl( authcProperties.getAuthzProxyUrl() );
	        } else {
	        	// Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
		        String callbackUrl = Pac4jUrlUtils.constructRedirectUrl(callbackProperties.getDefaultUrl(), pac4jProperties.getClientParameterName(), pac4jProperties.getDefaultClientName());
		        logoutFilter.setDefaultUrl( callbackUrl );
			}
	        logoutFilter.setDestroySession(pac4jLogoutProperties.isDestroySession());
	        logoutFilter.setLocalLogout(pac4jLogoutProperties.isLocalLogout());
	        logoutFilter.setLogoutLogic(logoutLogic);
	        logoutFilter.setLogoutUrlPattern(pac4jLogoutProperties.getPathPattern());
	        
		    return logoutFilter;
		}
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
   	    	http.requestMatchers()
   	    		.antMatchers(authcProperties.getPathPattern(), callbackProperties.getPathPattern())
   	    		.and()
   	    		.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.disable()
   	        	.addFilterBefore(localeContextFilter, SecurityFilter.class)
   	        	.addFilterBefore(pac4jSecurityFilter(), BasicAuthenticationFilter.class)
   	        	.addFilterBefore(pac4jCallbackFilter(), SecurityFilter.class)
   	        	.addFilterAt(pac4jLogoutFilter(), SecurityFilter.class);

   	    	super.configure(http, authcProperties.getCors());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    	 
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }

	}

}
