package com.arjunkumar.springsecurity.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private UserDetailsService userDetailsService;

    /** authentication */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // below code is for in-memory authentication
//        auth.inMemoryAuthentication()
//                .withUser("Arjun")
//                .password("password")
//                .roles("USER")
//                .and()
//                .withUser("Anuj")
//                .password("password2")
//                .roles("ADMIN");


        // code for jdbc authentication with default schema
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .withDefaultSchema()
//                .withUser(
//                        User.withUsername("user")
//                                .password("pass")
//                                .roles("USER")
//                )
//                .withUser(
//                        User.withUsername("admin")
//                                .password("pass")
//                                .roles("ADMIN")
//                );


        // code for jdbc authentication with custom schema
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .usersByUsernameQuery("select username, password, enabled from users where username = ?")
//                .authoritiesByUsernameQuery("select username, authority from authorities where username = ?");


        // code for authentication using custom userDetailsService
//        auth.userDetailsService(userDetailsService);

//        ldap authentication
        auth.ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                .contextSource()
                .url("ldap://localhost:8389/dc=springframework,dc=org")
                .and()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                // password while login for user ben is benspassword
                .passwordAttribute("userPassword");

    }

    /** authorization */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/admin").hasRole("ADMIN")
//                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
//                .antMatchers("/").permitAll()
//                .and().formLogin();


        // ldap authorisation
        http.authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .formLogin();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
