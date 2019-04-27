package org.springframework.security.boot;

import org.pac4j.core.config.Config;
import org.pac4j.spring.boot.ext.Pac4jPathBuilder;
import org.pac4j.spring.boot.ext.property.Pac4jLogoutProperties;
import org.pac4j.spring.boot.ext.property.Pac4jProperties;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.LogoutFilter;
import org.pac4j.springframework.security.web.Pac4jEntryPoint;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore(name = { 
	"org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration",
	"org.springframework.security.boot.SecurityBizWebFilterConfiguration"   // spring-boot-starter-security-biz
})
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = SecurityPac4jProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityPac4jProperties.class, Pac4jLogoutProperties.class, ServerProperties.class })
public class SecurityPac4jFilterAutoConfiguration implements ApplicationContextAware {

	private ApplicationContext applicationContext;

	@Autowired
	private Pac4jProperties pac4jProperties;
	@Autowired
	private Pac4jLogoutProperties logoutProperties;
	@Autowired
	private ServerProperties serverProperties;
	@Autowired
	private Pac4jPathBuilder pathBuilder;

    @Bean
	@ConditionalOnMissingBean
	public ObjectMapper objectMapper() {
		return new ObjectMapper();
	} 
	
    /**
	 * 账号注销过滤器 ：处理账号注销
	 */
	@Bean
	@ConditionalOnProperty(prefix = Pac4jLogoutProperties.PREFIX, value = "local-logout", havingValue = "true")
	public LogoutFilter j2eLocalLogoutFilter(Config config){
		
		LogoutFilter logoutFilter = new LogoutFilter();
	    
		// Whether the centralLogout must be performed（是否注销统一身份认证）
        logoutFilter.setCentralLogout(logoutProperties.isCentralLogout());
		// Security Configuration
        logoutFilter.setConfig(config);
        // Default logourl url
        logoutFilter.setDefaultUrl( pathBuilder.getLogoutURL(serverProperties.getServlet().getContextPath()) );
        // Whether the Session must be destroyed（是否销毁Session）
        logoutFilter.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
        logoutFilter.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
        logoutFilter.setLogoutUrlPattern(logoutProperties.getLogoutUrlPattern());
        
	    return logoutFilter;
	}
	
	/**
	 * 账号注销过滤器 ：处理账号注销
	 */
	@Bean
	@ConditionalOnProperty(prefix = Pac4jLogoutProperties.PREFIX, value = "central-logout", havingValue = "true")
	public LogoutFilter j2eCentralLogoutFilter(Config config){
		
		LogoutFilter logoutFilter = new LogoutFilter();
	    
		// Whether the centralLogout must be performed（是否注销统一身份认证）
        logoutFilter.setCentralLogout(true);
		// Security Configuration
        logoutFilter.setConfig(config);
        // Default logourl url
        logoutFilter.setDefaultUrl( pathBuilder.getLogoutURL(serverProperties.getServlet().getContextPath()) );
        // Whether the Session must be destroyed（是否销毁Session）
        logoutFilter.setDestroySession(logoutProperties.isDestroySession());
        // Whether the application logout must be performed（是否注销本地应用身份认证）
        logoutFilter.setLocalLogout(logoutProperties.isLocalLogout());
        // Pattern that logout urls must match（注销登录路径规则，用于匹配登录请求操作）
        logoutFilter.setLogoutUrlPattern(logoutProperties.getLogoutUrlPattern());
        
	    return logoutFilter;
	}
	
	/**
	 * 回调过滤器 ：处理登录后的回调访问
	 */
	@Bean
	public CallbackFilter j2eCallbackFilter(Config config){
		
	    CallbackFilter callbackFilter = new CallbackFilter();
	    
	    // Security Configuration
        callbackFilter.setConfig(config);
        // Default url after login if none was requested（登录成功后的重定向地址，等同于shiro的successUrl）
        callbackFilter.setDefaultUrl( pathBuilder.getLoginURL(serverProperties.getServlet().getContextPath()) );
        // Whether multiple profiles should be kept
        callbackFilter.setMultiProfile(pac4jProperties.isMultiProfile());
        
	    return callbackFilter;
	}
	
	/**
	 * 权限控制过滤器 ：实现权限认证
	 */
	@Bean
	public SecurityFilter j2eSecurityFilter(Config config){
		
		SecurityFilter securityFilter = new SecurityFilter();  
		
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

	@Autowired
    private Config config;
	
	protected void configure(HttpSecurity http) throws Exception {

		final CallbackFilter callbackFilter = new CallbackFilter(config);
        callbackFilter.setMultiProfile(true);

        final LogoutFilter logoutFilter = new LogoutFilter(config, "/?defaulturlafterlogout");
        logoutFilter.setDestroySession(true);
        logoutFilter.setSuffix("/pac4jLogout");

        http
                .authorizeRequests()
                    .antMatchers("/protected/**").authenticated()
                    .anyRequest().permitAll()
                .and()
                .exceptionHandling().authenticationEntryPoint(new Pac4jEntryPoint(config, "CasClient"))
                .and()
                .addFilterBefore(callbackFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(logoutFilter, CallbackFilter.class)
                .csrf().disable()
                .logout()
                    .logoutSuccessUrl("/");
        
        
    }
	
	@Configuration
    @Order(13)
    public static class Pac4jLogoutWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final LogoutFilter filter = new LogoutFilter(config, "/?defaulturlafterlogout");
            filter.setDestroySession(true);

            http.antMatcher("/pac4jLogout")
                .addFilterBefore(filter, BasicAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }
    }

    @Configuration
    @Order(14)
    public static class Pac4jCentralLogoutWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        protected void configure(final HttpSecurity http) throws Exception {

            final LogoutFilter filter = new LogoutFilter(config, "http://localhost:8080/?defaulturlafterlogoutafteridp");
            filter.setLocalLogout(false);
            filter.setCentralLogout(true);
            filter.setLogoutUrlPattern("http://localhost:8080/.*");

            http.antMatcher("/pac4jCentralLogout")
                .addFilterBefore(filter, BasicAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }
    }
	
	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
