package cn.netbuffer.springsecuritydemo.config;

import cn.netbuffer.springsecuritydemo.auth.provider.CustomAuthenticationProvider;
import cn.netbuffer.springsecuritydemo.component.CustomLogoutHandler;
import cn.netbuffer.springsecuritydemo.filter.CustomLoginFilter;
import cn.netbuffer.springsecuritydemo.filter.CustomTokenAuthenticationFilter;
import cn.netbuffer.springsecuritydemo.service.CustomUserDetailsService;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;

@Slf4j
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider()).authenticationProvider(customAuthenticationProvider());
    }

    @Bean(name = "customAuthenticationProvider")
    public AuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

    @Bean(name = "daoAuthenticationProvider")
    public AuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
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

    /**
     * open access for static file
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/*.html");
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
    public CustomLoginFilter customLoginFilter() throws Exception {
        //config custom login filter
        CustomLoginFilter customLoginFilter = new CustomLoginFilter();
        customLoginFilter.setAuthenticationManager(authenticationManagerBean());
        customLoginFilter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            User user = (User) authentication.getPrincipal();
            log.debug("process custom login response for [{}]", user.getUsername());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("user", user.getUsername());
            data.put("session", httpServletRequest.getSession().getId());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        customLoginFilter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.debug("process custom login fail [{}]", e.getMessage());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("msg", e.getMessage());
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        return customLoginFilter;
    }

    @Bean
    public CustomTokenAuthenticationFilter customTokenAuthenticationFilter() throws Exception {
        //config custom token auth filter
        CustomTokenAuthenticationFilter customTokenAuthenticationFilter = new CustomTokenAuthenticationFilter();
        customTokenAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        customTokenAuthenticationFilter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            String user = (String) authentication.getPrincipal();
            log.debug("process custom token login response for [{}]", user);
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("user", user);
            data.put("session", httpServletRequest.getSession().getId());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        customTokenAuthenticationFilter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.debug("process custom token login fail [{}]", e.getMessage());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("msg", e.getMessage());
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        return customTokenAuthenticationFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/your-login-path")
                .defaultSuccessUrl("/your-success-path")
                .permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/", "/info/**")
                .permitAll()
                .antMatchers("/admin/**")
                .hasAuthority("admin")
                .antMatchers("/test/**")
                .hasAuthority("test")
                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling()
                .accessDeniedPage("/403.html");
        http.logout()
                .addLogoutHandler(customLogoutHandler())
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .logoutSuccessUrl("/info");
        http.rememberMe()
                .rememberMeParameter("rme")
                .userDetailsService(userDetailsService())
                .tokenRepository(persistentTokenRepository());
        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieName("csrf-token");
        http.csrf()
                .csrfTokenRepository(cookieCsrfTokenRepository);
        http.addFilterAfter(customLoginFilter(), CorsFilter.class);
        http.addFilterAfter(customTokenAuthenticationFilter(), CorsFilter.class);
    }

}