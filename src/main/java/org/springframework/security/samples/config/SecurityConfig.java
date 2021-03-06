package org.springframework.security.samples.config;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:application.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static List<String> clients = Arrays.asList("github", "neo");

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests().anyRequest().authenticated()
//        .and()
//        .oauth2Login()
//        .clientRegistrationRepository(clientRegistrationRepository())
//        .authorizedClientService(authorizedClientService());

		http.authorizeRequests().antMatchers("/oauth_login").permitAll().anyRequest().authenticated().and()
				.oauth2Login().clientRegistrationRepository(clientRegistrationRepository())
				.authorizedClientService(authorizedClientService()).loginPage("/oauth_login");

		http.logout().logoutUrl("/logout").invalidateHttpSession(true);
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		List<ClientRegistration> registrations = clients.stream().map(c -> getRegistration(c))
				.filter(registration -> registration != null).collect(Collectors.toList());

		return new InMemoryClientRegistrationRepository(registrations);
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService() {

		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
	}

	private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

	@Autowired
	private Environment env;

	private ClientRegistration getRegistration(String client) {
		String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

		if (clientId == null) {
			return null;
		}

		String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");

//      if (client.equals("google")) {
//          return CommonOAuth2Provider.GOOGLE.getBuilder(client)
//            .clientId(clientId).clientSecret(clientSecret).build();
//      }
		if (client.equals("github")) {
			return CommonOAuth2Provider.GITHUB.getBuilder(client).clientId(clientId).clientSecret(clientSecret).build();
		}
		if (client.equals("neo")) {
			return NeoBuild(clientId, clientSecret).clientId(clientId).clientSecret(clientSecret).build();
		}
		return null;
	}

	protected final ClientRegistration.Builder getBuilder(String registrationId, ClientAuthenticationMethod method,
			String redirectUri) {
		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
		builder.clientAuthenticationMethod(method);
		builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		builder.redirectUriTemplate(redirectUri);
		return builder;
	}

	private ClientRegistration.Builder NeoBuild(String clientId, String clientSecret) {
		ClientRegistration.Builder builder = getBuilder("neo", ClientAuthenticationMethod.BASIC,
				"https://i075885trial-i075885useast-dev2-oauth-demo.cfapps.us10.hana.ondemand.com/login/oauth2/code/neo");
		builder.scope("view_photos");
		builder.authorizationUri("https://oauthasservices-i075885trial.hanatrial.ondemand.com/oauth2/api/v1/authorize");
		builder.tokenUri("https://oauthasservices-i075885trial.hanatrial.ondemand.com/oauth2/api/v1/token");
		builder.userInfoUri("https://oauthasservices-i075885trial.hanatrial.ondemand.com/oauth2");
		builder.userNameAttributeName("userId");
		builder.clientName("Neo");
		return builder;
	}
}