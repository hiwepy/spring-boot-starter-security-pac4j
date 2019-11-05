package org.springframework.security.boot;

import java.util.stream.Collectors;

import org.pac4j.core.config.Config;
import org.pac4j.core.ext.http.callback.QueryParameterCallbackUrlExtResolver;
import org.pac4j.spring.boot.Pac4jAutoConfiguration;
import org.pac4j.spring.boot.Pac4jLogoutProperties;
import org.pac4j.spring.boot.Pac4jProperties;
import org.pac4j.spring.boot.utils.Pac4jUrlUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.pac4j.Pac4jProxyReceptor;
import org.springframework.security.boot.pac4j.Pac4jRedirectionActionBuilder;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticatedSecurityFilter;
import org.springframework.security.boot.pac4j.authentication.Pac4jPreAuthenticationCallbackFilter;
import org.springframework.security.boot.pac4j.authentication.logout.Pac4jLogoutHandler;
import org.springframework.security.boot.pac4j.authorizer.Pac4jEntryPoint;
import org.springframework.security.boot.pac4j.http.ajax.Pac4jAjaxRequestResolver;
import org.springframework.security.boot.utils.StringUtils2;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@AutoConfigureAfter(Pac4jAutoConfiguration.class)
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
		String defaultUrl = StringUtils2.defaultString(pac4jProperties.getDefaultUrl(), pac4jProperties.getServiceUrl());
		logoutHandler.setDefaultUrl(defaultUrl);
        // Whether the Session must be destroyed（是否销毁Session）
		logoutHandler.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
		logoutHandler.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配注销请求操作）
		logoutHandler.setLogoutUrlPattern(logoutProperties.getPathPattern());
		
	    return logoutHandler;
	}
	
	@Bean
	public Pac4jProxyReceptor pac4jProxyReceptor(SecurityPac4jAuthcProperties authcProperties,
			@Autowired(required = false) JwtPayloadRepository jwtPayloadRepository, 
			UserDetailsServiceAdapter userDetailsService) {
		
		Pac4jRedirectionActionBuilder redirectionActionBuilder = new Pac4jRedirectionActionBuilder();
		redirectionActionBuilder.setCallbackUrl(authcProperties.getAuthzProxyUrl());
		redirectionActionBuilder.setJwtPayloadRepository(jwtPayloadRepository);
		redirectionActionBuilder.setUserDetailsService(userDetailsService);
		
		Pac4jAjaxRequestResolver ajaxRequestResolver = new Pac4jAjaxRequestResolver();
		ajaxRequestResolver.setJwtPayloadRepository(jwtPayloadRepository);
		ajaxRequestResolver.setUserDetailsService(userDetailsService);
		
		Pac4jProxyReceptor proxyReceptor = new Pac4jProxyReceptor();
		proxyReceptor.setCallbackUrl(authcProperties.getAuthzProxyUrl());
		proxyReceptor.setCallbackUrlResolver(new QueryParameterCallbackUrlExtResolver());
		proxyReceptor.setAjaxRequestResolver(ajaxRequestResolver);
		proxyReceptor.setRedirectionActionBuilder(redirectionActionBuilder);
		return proxyReceptor;
	}
	
	@Configuration
	@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
	@EnableConfigurationProperties({ SecurityPac4jProperties.class, SecurityPac4jAuthcProperties.class,
		SecurityPac4jCallbackProperties.class, Pac4jLogoutProperties.class, Pac4jProperties.class, ServerProperties.class })
	@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 20)
	static class Pac4jWebSecurityConfigurationAdapter extends SecurityBizConfigurerAdapter {

		private final Pac4jProperties pac4jProperties;
		private final Pac4jLogoutProperties pac4jLogoutProperties;
		private final SecurityPac4jAuthcProperties authcProperties;
		private final SecurityPac4jCallbackProperties callbackProperties;
		
	    private final Config pac4jConfig;
	    private final LogoutHandler logoutHandler;
	    private final Pac4jEntryPoint authenticationEntryPoint;
    	private final RequestCache requestCache;
    	private final Pac4jProxyReceptor pac4jProxyReceptor;
    	    
		public Pac4jWebSecurityConfigurationAdapter(
				
				SecurityBizProperties bizProperties,
				SecurityPac4jAuthcProperties authcProperties,
				SecurityPac4jCallbackProperties callbackProperties,
				Pac4jProperties pac4jProperties,
				Pac4jLogoutProperties pac4jLogoutProperties,
				
				ObjectProvider<AuthenticationProvider> authenticationProvider,
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<Pac4jProxyReceptor> pac4jProxyReceptorProvider,
				ObjectProvider<Config> pac4jConfigProvider,
				ObjectProvider<LogoutHandler> logoutHandlerProvider,
				ObjectProvider<Pac4jEntryPoint> authenticationEntryPointProvider
				
			) {
			
			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
			
			this.pac4jProperties = pac4jProperties;
			this.authcProperties = authcProperties;
			this.callbackProperties = callbackProperties;
			this.pac4jLogoutProperties = pac4jLogoutProperties;
			
			this.authenticationEntryPoint = authenticationEntryPointProvider.getIfAvailable();
			this.pac4jProxyReceptor = pac4jProxyReceptorProvider.getIfAvailable();
			this.pac4jConfig = pac4jConfigProvider.getIfAvailable();
			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
   			this.requestCache = super.requestCache();
   			
		}

		
		/**
		 * 权限控制过滤器 ：实现权限认证
		 */
		public Pac4jPreAuthenticatedSecurityFilter pac4jSecurityFilter() throws Exception {
			
			Pac4jPreAuthenticatedSecurityFilter securityFilter = new Pac4jPreAuthenticatedSecurityFilter();  
			
			securityFilter.setAuthenticationManager(authenticationManagerBean());
			if (StringUtils2.hasText(authcProperties.getPathPattern())) {
				securityFilter.setFilterProcessesUrl(authcProperties.getPathPattern());
			}
			// 前后端分离
			if(authcProperties.isAuthzProxy() && pac4jProxyReceptor != null) {
				securityFilter.setProxyReceptor(pac4jProxyReceptor);
			}
			// List of authorizers
			securityFilter.setAuthorizers(pac4jProperties.getAuthorizers());
			// List of clients for authentication
			securityFilter.setClients(pac4jProperties.getClients());
			// Security configuration
			securityFilter.setConfig(pac4jConfig);
			securityFilter.setMatchers(pac4jProperties.getMatchers());
			// Whether multiple profiles should be kept
			securityFilter.setMultiProfile(pac4jProperties.isMultiProfile());
			
		    return securityFilter;
		}
		
		/**
		 * 回调过滤器 ：处理登录后的回调访问
		 */
		public Pac4jPreAuthenticationCallbackFilter pac4jCallbackFilter() throws Exception {
			
			Pac4jPreAuthenticationCallbackFilter callbackFilter = new Pac4jPreAuthenticationCallbackFilter();
		    
			callbackFilter.setAuthenticationManager(authenticationManager());
			if (StringUtils2.hasText(callbackProperties.getPathPattern())) {
				callbackFilter.setFilterProcessesUrl(callbackProperties.getPathPattern());
			}
			
		    // Security Configuration
	        callbackFilter.setConfig(pac4jConfig);
	        
	        // 前后端分离模式
	        if(authcProperties.isAuthzProxy()) {
	        	callbackFilter.setDefaultUrl( authcProperties.getAuthzProxyUrl() );
	        } else {
	        	// Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
		        String defaultUrl = StringUtils2.defaultString(callbackProperties.getDefaultUrl(), pac4jProperties.getServiceUrl());
		        String callbackUrl = Pac4jUrlUtils.constructRedirectUrl(defaultUrl, pac4jProperties.getClientParameterName(), pac4jProperties.getDefaultClientName());
		        callbackFilter.setDefaultUrl( callbackUrl );
			}
	        
	        // Whether multiple profiles should be kept
	        callbackFilter.setMultiProfile(pac4jProperties.isMultiProfile());
	        
		    return callbackFilter;
		}
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			
   	    	http.requestCache()
   	        	.requestCache(requestCache)
   	        	// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.logoutUrl(pac4jLogoutProperties.getPathPattern())
   	    		.logoutSuccessUrl(StringUtils2.defaultString(pac4jProperties.getDefaultUrl(), pac4jProperties.getServiceUrl()))
   	    		.addLogoutHandler(logoutHandler)
   	    		.clearAuthentication(true)
   	    		.invalidateHttpSession(true)
   	        	// 异常处理
   	        	.and()
   	        	.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.requestMatchers()
 				.antMatchers(authcProperties.getPathPattern(), callbackProperties.getPathPattern())
 				.and()
   	        	.addFilterBefore(pac4jSecurityFilter(), BasicAuthenticationFilter.class)
   	        	.addFilterBefore(pac4jCallbackFilter(), Pac4jPreAuthenticatedSecurityFilter.class);

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
