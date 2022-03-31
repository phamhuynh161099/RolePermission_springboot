package com.fpt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	@Autowired
	private UserPrincipalDetailsServcie userPrincipalDetailsServcie;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		 http
         .authorizeRequests()
         .antMatchers("/index.html").permitAll()
         .antMatchers("/profile/**").authenticated()
         .antMatchers("/admin/**").hasRole("ADMIN")
         .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
         .antMatchers("/api/test1").hasAuthority("A_T1")
         .antMatchers("/api/test2").hasAuthority("A_T2")
//         .antMatchers("/api/test1").permitAll()
//         .antMatchers("/api/test2").permitAll()
         .and()
         /*.httpBasic();*/
         .formLogin()
         .loginPage("/login").permitAll()
         .and()
         .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/login")
         .and().rememberMe().tokenValiditySeconds(2592000).key("mySecret!");
		 
		 
			/*
			 * .formLogin() .loginProcessingUrl("/signin") .loginPage("/login").permitAll()
			 * .usernameParameter("txtUsername") .passwordParameter("txtPassword")
			 * 
			 * code customer
			 */
	}
	
	
	/**
	 * Them Servie cap nat principal vao security
	 * */
	DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userPrincipalDetailsServcie);

        return daoAuthenticationProvider;
	}
	
	@Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }
	
}
