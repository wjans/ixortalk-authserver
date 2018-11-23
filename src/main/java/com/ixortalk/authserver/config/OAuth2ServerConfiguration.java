/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-present IxorTalk CVBA
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.ixortalk.authserver.config;

import com.ixortalk.authserver.security.AuthoritiesConstants;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementServerProperties;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;

import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.stream.Collectors.toSet;
import static org.springframework.boot.autoconfigure.security.SecurityProperties.BASIC_AUTH_ORDER;
import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;
import static org.springframework.util.StringUtils.hasText;

@Configuration
public class OAuth2ServerConfiguration {

    public static final int LOGIN_CONFIG_ORDER = BASIC_AUTH_ORDER + 1;

    @EnableResourceServer
    public static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        private final TokenStore tokenStore;

        private final CorsFilter corsFilter;

        public ResourceServerConfiguration(TokenStore tokenStore, CorsFilter corsFilter) {
            this.tokenStore = tokenStore;
            this.corsFilter = corsFilter;
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .csrf()
                .disable()
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .headers()
                .frameOptions()
                .disable()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/register").permitAll()
                .antMatchers("/api/activate").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/account/reset-password/init").permitAll()
                .antMatchers("/api/account/reset-password/finish").permitAll()
                .antMatchers("/api/**").authenticated()
                .antMatchers("/management/health").permitAll()
                .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
                .antMatchers("/v2/api-docs/**").permitAll()
                .antMatchers("/swagger-resources/configuration/ui").permitAll()
                .antMatchers("/swagger-ui/index.html").hasAuthority(AuthoritiesConstants.ADMIN);
        }

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            resources.resourceId("jhipster-uaa").tokenStore(tokenStore);
        }
    }

    @Configuration
    @EnableAuthorizationServer
    @Order(LOWEST_PRECEDENCE - 2)
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Inject
        private DataSource dataSource;

        @Inject
        private JHipsterProperties jHipsterProperties;

        @Inject
        private IxorTalkProperties ixorTalkProperties;

        @Inject
        private PasswordEncoder passwordEncoder;

        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Inject
        @Qualifier("authenticationManagerBean")
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {

            endpoints
                .tokenStore(tokenStore())
                .authenticationManager(authenticationManager);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
            oauthServer.allowFormAuthenticationForClients();
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            if (ixorTalkProperties.getOauth().getClients().isUseJdbc()) {
                clients.jdbc(dataSource);
                cleanUpClientsFromConfiguration();
            } else {
                clients.inMemory();

            }
            jHipsterProperties.getSecurity().getAuthentication().getOauthClients().values()
                .stream()
                .forEach(client ->
                    clients
                        .and()
                        .withClient(client.getClientid())
                        .scopes(client.getScopes().toArray(new String[]{}))
                        .authorities(client.getAuthorities().toArray(new String[]{}))
                        .authorizedGrantTypes(client.getAuthorizedGrantTypes().toArray(new String[]{}))
                        .autoApprove(client.getAutoApproveScopes().toArray(new String[]{}))
                        .secret(passwordEncoder.encode(client.getSecret()))
                        .accessTokenValiditySeconds(client.getTokenValidityInSeconds())
                );
        }

        public void cleanUpClientsFromConfiguration() {
            JdbcClientDetailsService jdbcClientDetailsService = new JdbcClientDetailsService(dataSource);
            Set<String> existingClientIds = jdbcClientDetailsService.listClientDetails().stream().map(ClientDetails::getClientId).collect(toSet());
            jHipsterProperties.getSecurity().getAuthentication().getOauthClients().values()
                .stream()
                .filter(client -> existingClientIds.contains(client.getClientid()))
                .forEach(client -> jdbcClientDetailsService.removeClientDetails(client.getClientid()));
        }

        @Configuration
        @Order(LOGIN_CONFIG_ORDER)
        protected static class LoginConfig extends WebSecurityConfigurerAdapter {

            @Value("${defaultSuccessUrl}")
            private String defaultSuccessUrl;

            @Value("${loginPage}")
            private String loginPage;

            @Inject
            private ManagementServerProperties managementServerProperties;

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // @formatter:off
                ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry registry =
                    http
                        .formLogin()
                        .loginPage(loginPage)
                        .defaultSuccessUrl(defaultSuccessUrl)
                        .permitAll()
                        .and()
                        .requestMatchers()
                        .antMatchers(requestMatchers())
                        .and()
                        .logout()
                        .logoutRequestMatcher(new AntPathRequestMatcher("/signout"))
                        .logoutSuccessUrl("/login")
                        .and()
                        .authorizeRequests()
                        .antMatchers("/").permitAll();

                if (hasText(managementServerProperties.getServlet().getContextPath())) {
                    registry = registry.antMatchers(managementServerProperties.getServlet().getContextPath() + "/**").permitAll();
                }

                registry
                    .anyRequest()
                    .authenticated();
                // @formatter:on
            }

            private String[] requestMatchers() {
                List<String> requestMatchers = newArrayList("/login", "/signout", "/reset", "/", "/oauth/authorize", "/oauth/confirm_access");
                if (hasText(managementServerProperties.getServlet().getContextPath())) {
                    requestMatchers.add(managementServerProperties.getServlet().getContextPath() + "/**");
                }
                return requestMatchers.toArray(new String[0]);
            }

        }
    }
}
