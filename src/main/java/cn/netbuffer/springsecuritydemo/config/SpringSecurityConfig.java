package cn.netbuffer.springsecuritydemo.config;

import cn.netbuffer.springsecuritydemo.component.CustomLogoutHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.annotation.Resource;

@Slf4j
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

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

    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private CustomLogoutHandler customLogoutHandler;

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

    }

}