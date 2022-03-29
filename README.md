# security-pac4j-spring-boot-starter

### 组件简介

> 基于 Security + Pac4j 的 Spring Boot Starter 实现

主要 扩展Security、Pac4j 与Spring Boot的整合，实现通过yaml配置即可实现权限拦截扩展，类似Shiro的 shiro.ini 配置方式

### 使用说明

##### 1、Spring Boot 项目添加 Maven 依赖

``` xml
<dependency>
	<groupId>com.github.hiwepy</groupId>
	<artifactId>security-pac4j-spring-boot-starter</artifactId>
	<version>${project.version}</version>
</dependency>
```

##### 2、在`application.yml`文件中增加如下配置

```yaml
################################################################################################################
###Pac4j 第三方登录（QQ、微信、易班、康赛）配置：
################################################################################################################
pac4j:
  enabled: true
  default-client-name: uniauth
  callback-url: http://localhost:8088/authz/login/pac4j?client_name=uniauth&proxy=false
  callback-url-fixed: false
  client-parameter-name: client_name
  clients: uniauth
  logout:
    path-pattern: /**/logout/pac4j
  cas:
    enabled: true
    accept-any-proxy: true
    gateway: false
    login-url: http://localhost/sso/login
    logout-url: http://localhost/sso/logout
    prefix-url: http://localhost/sso/
    protocol: cas20-proxy
    renew: false
    service-url: http://localhost:8088/authz
    # Cas客户端配置
    #cas-client: true
    #cas-client-name: cas
    # Cas代理客户端配置
    direct-cas-client: true
    direct-cas-client-name: cas
    #direct-cas-proxy-client: true
    #direct-cas-proxy-client-name: cas-proxy
  uniauth:
    enabled: true
    token:
      profile-url: http://localhost:8080/yyxy_uniauth/ser/vaildTocken.action
      custom-params:
        syskey: xxxxxxxxx
      support-post-request: true
      support-get-request: true
  oauth:
    yiban:
      name: yiban
      
spring:
  # Spring Security 配置
  security:
    # 默认路径拦截规则定义
    filter-chain-definition-map:
      '[/]' : anon
      '[/**/favicon.ico]' : anon
      '[/webjars/**]': anon
      '[/assets/**]' : anon
      '[/error*]' : anon
      '[/logo/**]' : anon
      '[/swagger-ui.html**]' : anon
      '[/swagger-resources/**]' : anon
      '[/doc.html**]' : anon
      '[/bycdao-ui/**]' : anon
      '[/v2/**]' : anon
      '[/kaptcha*]' : anon
      '[/actuator*]' : anon
      '[/actuator/**]' : anon
      '[/druid/*]' : ipaddr[192.168.1.0/24]
      '[/monitoring]' : roles[admin]
      '[/monitoring2]' : roles[1,admin]
      '[/monitoring3]' : perms[1,admin]
      '[/monitoring4]' : perms[1]
    #  第三方登录
    pac4j:
      enabled: true
      authc:
        path-pattern: /authz/login/pac4j
        authz-proxy: false
        authz-proxy-url: http://localhost:8089/#/client?client_name=cas&target=/portal
        redirects:
          - header-pattern:
              '[x-requested-with]' : com.yiban.app
            redirect-url: http://localhost:8089/#/client?client_name=cas&target=/portal
            error-url: http://localhost:8089/#/client?client_name=cas&target=/portal
      callback:
        path-pattern: /authz/login/pac4j/callback
        redirects:
          - header-pattern:
              token : '*'
            callback-url: http://localhost:8089/#/client?client_name=cas&target=/portal
```

##### 3、使用示例

```java
 SecurityPrincipal principal = SubjectUtils.getPrincipal(SecurityPrincipal.class);
```

## Jeebiz 技术社区

Jeebiz 技术社区 **微信公共号**、**小程序**，欢迎关注反馈意见和一起交流，关注公众号回复「Jeebiz」拉你入群。

|公共号|小程序|
|---|---|
| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/qrcode_for_gh_1d965ea2dfd1_344.jpg)| ![](https://raw.githubusercontent.com/hiwepy/static/main/images/gh_09d7d00da63e_344.jpg)|


