package com.qa.Gateway.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtConfig jwtConfig;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				// make sure we use stateless session; session won't be used to store user's
				// state.
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				// handle an authorized attempts
				.exceptionHandling()
				.authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)).and()
				// Add a filter to validate the tokens with every request
				.addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
				// authorization requests config
				.authorizeRequests()
				// allow all who are accessing "auth" service
				.antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
				// must be an admin if trying to access admin area (authentication is also
				// required here)
				.antMatchers("/tm**").hasRole("TRAINING_MANAGER")
				.antMatchers("/trainee/uploadCV/{username}").authenticated()
				.antMatchers("/trainee/getCVByID/{id}").hasAnyRole("TRAINER", "TRAINING_MANAGER")
				.antMatchers("/trainee/getCVByID/{id}").authenticated()
				.antMatchers("/trainee/getAllCVs").hasAnyRole("TRAINER", "TRAINING_MANAGER")
				.antMatchers("/trainee/getCVfor/{username}").hasAnyRole("TRAINER", "TRAINING_MANAGER")
				.antMatchers("/trainee/getCVfor/{username}").authenticated()
				.antMatchers("/trainee/deleteCV/{cvID}").authenticated()
				.antMatchers("/trainee/addUser").permitAll()
				.antMatchers("/trainee/getUser/{username}").hasAnyRole("TRAINER", "TRAINING_MANAGER")
				.antMatchers("/trainee/getAll").hasAnyRole("TRAINER", "TRAINING_MANAGER")
				.antMatchers("/trainee/updateUser/{username}").authenticated()
				.antMatchers("/trainee/deleteUser/{username}").hasRole("TRAINING_MANAGER")
				.antMatchers("/trainer/addUser").hasRole("TRAINING_MANAGER")
				.antMatchers("/trainer/deleteUser/{username}").hasRole("TRAINING_MANAGER")
				.antMatchers("/trainer/updateUser/{username}").authenticated()
				.antMatchers("/trainer/getUser/{username}").hasRole("TRAINING_MANAGER")
				.antMatchers("/trainer/getAll").hasRole("TRAINING_MANAGER")
				// Any other request must be authenticated
				.anyRequest().authenticated();
	}

	@Bean
	public JwtConfig jwtConfig() {
		return new JwtConfig();
	}

}
