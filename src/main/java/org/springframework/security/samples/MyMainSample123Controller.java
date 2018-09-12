/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.samples;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.ModelAndView;

import reactor.core.publisher.Mono;

/**
 * @author Joe Grandja
 */
@Controller
public class MyMainSample123Controller {

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@RequestMapping("/")
	public String index(Model model, OAuth2AuthenticationToken authentication) {
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		model.addAttribute("userName", authentication.getName());
		model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
		return "index";
	}

	@RequestMapping(value = "/userinfo", method = RequestMethod.GET)
	public String userinfo(Model model, OAuth2AuthenticationToken authentication) {
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		Map userAttributes = Collections.emptyMap();
		String userInfoEndpointUri = authorizedClient.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
				.getUri();
		if (!StringUtils.isEmpty(userInfoEndpointUri)) { // userInfoEndpointUri is optional for OIDC Clients
			userAttributes = WebClient.builder().filter(oauth2Credentials(authorizedClient)).build().get()
					.uri(userInfoEndpointUri).retrieve().bodyToMono(Map.class).block();
		}
		model.addAttribute("userAttributes", userAttributes);
		return "userinfo";
	}

	private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
		return this.authorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(),
				authentication.getName());
	}

	private ExchangeFilterFunction oauth2Credentials(OAuth2AuthorizedClient authorizedClient) {
		return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
			ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
					.header(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
					.build();
			return Mono.just(authorizedRequest);
		});
	}

	private static String authorizationRequestBaseUri = "oauth2/authorization";
	Map<String, String> oauth2AuthenticationUrls = new HashMap<>();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@RequestMapping(value = "/oauth_login", method = RequestMethod.GET)
	public String getLoginPage(Model model) {
		Iterable<ClientRegistration> clientRegistrations = null;
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}

		clientRegistrations.forEach(registration -> oauth2AuthenticationUrls.put(registration.getClientName(),
				authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
		model.addAttribute("urls", oauth2AuthenticationUrls);

		return "oauth_login";
	}

	@RequestMapping(value = "/test", method = RequestMethod.GET)
	public ModelAndView test() {
		ModelAndView mv = new ModelAndView("test");
		mv.getModel().put("msg", "hellooooo");
		mv.getModel().put("userName", "xxxx");
		return mv;
	}

	@ModelAttribute
	public void addAttributes(Model model) {
		model.addAttribute("msg", "Welcome to the Netherlands!");
	}
}
