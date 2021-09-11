package cn.netbuffer.springsecuritydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
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
                .csrf()
                .disable();

    }

}