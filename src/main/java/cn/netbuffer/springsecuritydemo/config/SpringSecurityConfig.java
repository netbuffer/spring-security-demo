package cn.netbuffer.springsecuritydemo.config;

import cn.netbuffer.springsecuritydemo.component.CustomLogoutHandler;
import cn.netbuffer.springsecuritydemo.filter.CustomLoginFilter;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;
import javax.annotation.Resource;

@Slf4j
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter implements ApplicationContextAware {

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
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher
            (ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        log.debug("init InMemoryTokenRepositoryImpl");
        return new InMemoryTokenRepositoryImpl();
    }

    @Resource(name = "customUserDetailsService")
    private UserDetailsService userDetailsService;
    @Resource
    private CustomLogoutHandler customLogoutHandler;

    private CustomLoginFilter customLoginFilter = new CustomLoginFilter();

    @Resource
    private AuthenticationManager authenticationManager;

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
                .addLogoutHandler(customLogoutHandler)
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .logoutSuccessUrl("/info");
        http.rememberMe()
                .rememberMeParameter("rme")
                .userDetailsService(userDetailsService)
                .tokenRepository(persistentTokenRepository());
        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieName("csrf-token");
        http.csrf()
                .csrfTokenRepository(cookieCsrfTokenRepository);
        customLoginFilter.setAuthenticationManager(authenticationManager);
        customLoginFilter.setAuthenticationSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
            User user = (User) authentication.getPrincipal();
            log.debug("process [{}] login response", user.getUsername());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("user", user.getUsername());
            data.put("session", httpServletRequest.getSession().getId());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        customLoginFilter.setAuthenticationFailureHandler((httpServletRequest, httpServletResponse, e) -> {
            log.debug("process login fail [{}]", e.getMessage());
            httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
            JSONObject data = new JSONObject();
            data.put("msg", e.getMessage());
            httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
            httpServletResponse.getWriter().write(data.toJSONString());
        });
        http.addFilterAfter(customLoginFilter, CorsFilter.class);
    }

}