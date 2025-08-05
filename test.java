import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OverrideAuthorizationHeaderFilterTest {

    @Mock
    private AuthorizationConfiguration authorizationConfiguration;

    @Mock
    private GatewayFilterChain chain;

    @InjectMocks
    private OverrideAuthorizationHeaderFilter filter;

    private ServerWebExchange exchange;

    @BeforeEach
    void setUp() {
        // Domyślny mock exchange
        ServerHttpRequest request = MockServerHttpRequest.get("/test").build();
        exchange = MockServerWebExchange.from(request);
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());
    }

    private void mockSecurityContext(Authentication authentication) {
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));
    }
}

@Test
void shouldApplyFilterAndAddAuthorizationHeaderWhenServiceEligibleForOverrideAndAuthenticatedAndNoAuthorizationDefined() {
    // Arrange: Serwis eligible, authenticated, authorized, brak istniejącego Authorization
    exchange.getAttributes().put("serviceId", "some-service-id");
    when(authorizationConfiguration.requiresBasicAuth("some-service-id")).thenReturn(true);
    when(authorizationConfiguration.getBasicAuthForService("some-service-id")).thenReturn("dXNlcjpwYXNz"); // Base64 "user:pass"

    Authentication auth = mock(Authentication.class);
    when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_TEST")));
    when(auth.getPrincipal()).thenReturn("user");
    mockSecurityContext(auth);

    when(authorizationConfiguration.getRequiredAuthorities("some-service-id")).thenReturn(Set.of("ROLE_TEST"));

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain).filter(any(ServerWebExchange.class));
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    assert authHeader != null && authHeader.equals("Basic dXNlcjpwYXNz");
}

@Test
void shouldApplyFilterAndAddAuthorizationHeaderWhenServiceEligibleForOverrideAndAuthenticatedAndAuthorized() {
    // Arrange: Podobnie jak powyżej, ale z istniejącym headerem do override
    exchange.getRequest().mutate().header(HttpHeaders.AUTHORIZATION, "Bearer old-token");
    exchange.getAttributes().put("serviceId", "some-service-id");
    when(authorizationConfiguration.requiresBasicAuth("some-service-id")).thenReturn(true);
    when(authorizationConfiguration.getBasicAuthForService("some-service-id")).thenReturn("dXNlcjpwYXNz");

    Authentication auth = mock(Authentication.class);
    when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_TEST")));
    when(auth.getPrincipal()).thenReturn("user");
    mockSecurityContext(auth);

    when(authorizationConfiguration.getRequiredAuthorities("some-service-id")).thenReturn(Set.of("ROLE_TEST"));

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain).filter(any(ServerWebExchange.class));
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    assert authHeader.equals("Basic dXNlcjpwYXNz"); // Nadpisany
}

@Test
void shouldNotApplyFilterWhenServiceEligibleForOverrideAndAuthenticatedButNotAuthorized() {
    // Arrange: Eligible, authenticated, ale not authorized
    exchange.getAttributes().put("serviceId", "some-service-id");
    when(authorizationConfiguration.requiresBasicAuth("some-service-id")).thenReturn(true);

    Authentication auth = mock(Authentication.class);
    when(auth.getAuthorities()).thenReturn(Collections.emptyList());
    when(auth.getPrincipal()).thenReturn("user");
    mockSecurityContext(auth);

    when(authorizationConfiguration.getRequiredAuthorities("some-service-id")).thenReturn(Set.of("ROLE_ADMIN"));

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain, never()).filter(any());
    assert exchange.getResponse().getStatusCode() == HttpStatus.FORBIDDEN;
    assert exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null;
}

@Test
void shouldNotApplyFilterWhenServiceNotEligibleForOverride() {
    // Arrange: Service not eligible (nie wymaga Basic Auth)
    exchange.getAttributes().put("serviceId", "non-eligible-service-id");
    when(authorizationConfiguration.requiresBasicAuth("non-eligible-service-id")).thenReturn(false);

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain).filter(exchange);
    assert exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null;
}

@Test
void shouldNotFailAndNotApplyFilterWhenNoServiceEligibleForOverrideDefined() {
    // Arrange: Brak serviceId (resolveServiceId zwraca null)
    // Symulacja braku attribute
    when(authorizationConfiguration.requiresBasicAuth(anyString())).thenReturn(false); // Fallback

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain).filter(exchange);
    verify(authorizationConfiguration, never()).getBasicAuthForService(anyString());
    assert exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null;
}

@Test
void shouldNotApplyFilterWhenNoSecurityContext() {
    // Arrange: Eligible, ale brak SecurityContext
    exchange.getAttributes().put("serviceId", "some-service-id");
    when(authorizationConfiguration.requiresBasicAuth("some-service-id")).thenReturn(true);

    ReactiveSecurityContextHolder.withSecurityContext(Mono.empty());

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain, never()).filter(any());
    assert exchange.getResponse().getStatusCode() == HttpStatus.FORBIDDEN;
}

@Test
void shouldApplyFilterAndAddAuthorizationHeaderWhenServiceEligibleForOverrideAndPostMethod() {
    // Dodatkowy test na metodę POST, jak w starych testach
    ServerHttpRequest postRequest = MockServerHttpRequest.method(HttpMethod.POST, "/api/v1/secured-endpoint").build();
    exchange = MockServerWebExchange.from(postRequest);
    exchange.getAttributes().put("serviceId", "some-service-id");
    when(authorizationConfiguration.requiresBasicAuth("some-service-id")).thenReturn(true);
    when(authorizationConfiguration.getBasicAuthForService("some-service-id")).thenReturn("dXNlcjpwYXNz");

    Authentication auth = mock(Authentication.class);
    when(auth.getAuthorities()).thenReturn(List.of(new SimpleGrantedAuthority("ROLE_TEST")));
    when(auth.getPrincipal()).thenReturn("user");
    mockSecurityContext(auth);

    when(authorizationConfiguration.getRequiredAuthorities("some-service-id")).thenReturn(Set.of("ROLE_TEST"));

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    verify(chain).filter(any(ServerWebExchange.class));
    String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    assert authHeader.equals("Basic dXNlcjpwYXNz");
}
