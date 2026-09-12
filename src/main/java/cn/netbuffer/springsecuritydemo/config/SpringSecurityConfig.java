package cn.netbuffer.springsecuritydemo.config;

import cn.netbuffer.springsecuritydemo.auth.provider.CustomAuthenticationProvider;
import cn.netbuffer.springsecuritydemo.component.CustomLogoutHandler;
import cn.netbuffer.springsecuritydemo.filter.CsrfCookieFilter;
import cn.netbuffer.springsecuritydemo.filter.CustomLoginFilter;
import cn.netbuffer.springsecuritydemo.filter.CustomTokenAuthenticationFilter;
import cn.netbuffer.springsecuritydemo.permission.SsdPermissionEvaluator;
import cn.netbuffer.springsecuritydemo.service.CustomUserDetailsService;
import com.alibaba.fastjson2.JSONObject;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * Spring Security 核心配置
 *
 * <p>Spring Security 7 起已移除 {@code WebSecurityConfigurerAdapter}，统一采用
 * {@link SecurityFilterChain} Bean + Lambda DSL 方式配置过滤器链。</p>
 * <p>{@link EnableMethodSecurity} 替代已废弃的 {@code @EnableGlobalMethodSecurity}，
 * 开启 {@code @Secured} / {@code @PreAuthorize} 等方法级注解鉴权。</p>
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SpringSecurityConfig {

    @Resource
    private SsdPermissionEvaluator ssdPermissionEvaluator;

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(ssdPermissionEvaluator);
        return expressionHandler;
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new ProviderManager(providers);
    }

    @Bean(name = "customAuthenticationProvider")
    public AuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean(name = "daoAuthenticationProvider")
    public AuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
                                                            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean(name = "customUserDetailsService")
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    @Bean(name = "customLogoutHandler")
    public LogoutHandler customLogoutHandler() {
        return new CustomLogoutHandler();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        log.debug("init InMemoryTokenRepositoryImpl for rememberme");
        return new InMemoryTokenRepositoryImpl();
    }

    @Bean
    public CookieCsrfTokenRepository cookieCsrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookieName("csrf-token");
        repository.setHeaderName("X-CSRF-TOKEN");
        repository.setCookiePath("/");
        return repository;
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public CustomLoginFilter customLoginFilter(AuthenticationManager authenticationManager,
                                               SecurityContextRepository securityContextRepository) {
        CustomLoginFilter customLoginFilter = new CustomLoginFilter();
        customLoginFilter.setAuthenticationManager(authenticationManager);
        customLoginFilter.setSecurityContextRepository(securityContextRepository);
        customLoginFilter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            Object principal = authentication.getPrincipal();
            String username = principal instanceof UserDetails userDetails ? userDetails.getUsername() : String.valueOf(principal);
            log.debug("process custom login response for [{}]", username);
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            JSONObject data = new JSONObject();
            data.put("user", username);
            data.put("session", httpServletRequest.getSession().getId());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        customLoginFilter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.debug("process custom login fail [{}]", e.getMessage());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            JSONObject data = new JSONObject();
            data.put("msg", e.getMessage());
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        return customLoginFilter;
    }

    @Bean
    public CustomTokenAuthenticationFilter customTokenAuthenticationFilter(AuthenticationManager authenticationManager,
                                                                           SecurityContextRepository securityContextRepository) {
        CustomTokenAuthenticationFilter customTokenAuthenticationFilter = new CustomTokenAuthenticationFilter();
        customTokenAuthenticationFilter.setAuthenticationManager(authenticationManager);
        customTokenAuthenticationFilter.setSecurityContextRepository(securityContextRepository);
        customTokenAuthenticationFilter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            Object principal = authentication.getPrincipal();
            String username = principal instanceof UserDetails userDetails ? userDetails.getUsername() : String.valueOf(principal);
            log.debug("process custom token login response for [{}]", username);
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            JSONObject data = new JSONObject();
            data.put("user", username);
            data.put("session", httpServletRequest.getSession().getId());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        customTokenAuthenticationFilter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.debug("process custom token login fail [{}]", e.getMessage());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            JSONObject data = new JSONObject();
            data.put("msg", e.getMessage());
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        return customTokenAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CustomLoginFilter customLoginFilter,
                                                   CustomTokenAuthenticationFilter customTokenAuthenticationFilter) throws Exception {
        http
                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/your-login-path")
                        .defaultSuccessUrl("/info")
                        .failureUrl("/login.html?error")
                        .permitAll())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/info/**",
                                "/login.html",
                                "/logout.html",
                                "/custom-login.html",
                                "/custom-token-login.html",
                                "/403.html",
                                "/tailwind.js",
                                "/your-custom-login-path",
                                "/your-custom-token-login-path"
                        ).permitAll()
                        .requestMatchers("/admin/**").hasAuthority("admin")
                        .requestMatchers("/test/**").hasAuthority("test")
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex.accessDeniedPage("/403.html"))
                .logout(logout -> logout
                        .addLogoutHandler(customLogoutHandler())
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/info"))
                .rememberMe(remember -> remember
                        .rememberMeParameter("rme")
                        .userDetailsService(userDetailsService())
                        .tokenRepository(persistentTokenRepository()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieCsrfTokenRepository())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/your-custom-login-path", "/your-custom-token-login-path"))
                .addFilterAfter(new CsrfCookieFilter(), org.springframework.security.web.csrf.CsrfFilter.class)
                .addFilterAfter(customLoginFilter, CorsFilter.class)
                .addFilterAfter(customTokenAuthenticationFilter, CorsFilter.class);
        return http.build();
    }

}
