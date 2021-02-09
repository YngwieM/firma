package be.vdab.firma.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.sql.DataSource;

@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final DataSource datasource;
    SecurityConfig(DataSource datasource) {
        this.datasource = datasource;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin();
        http.authorizeRequests(requests -> requests
                .mvcMatchers("/geluk").hasAuthority("gebruiker"));
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(datasource)
                .usersByUsernameQuery(
                        "select emailAdres as username, paswoord as password, true as enabled" +
                                " from werknemers where emailAdres = ?")
                .authoritiesByUsernameQuery("select ?, 'gebruiker'");
    }
}