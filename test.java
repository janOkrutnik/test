import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.test.context.support.TestingAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeUtils;
import reactor.core.publisher.Context;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class AddUserHeaderAndParamFilterTest {

    private AddUserHeaderAndParamFilter filter;

    @Mock
    private AuthorizationConfiguration authorizationConfiguration;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        filter = new AddUserHeaderAndParamFilter(authorizationConfiguration);
    }

    // Metoda authContextWithJwtClaim dostosowana do AuthenticatedUser (jak w Zuul testach)
    private Context authContextWithJwtClaim(String claimKey, String claimValue) {
        AuthenticatedUser authenticatedUser = (claimValue != null) ? new AuthenticatedUser(claimValue) : null;  // Zakładam konstruktor z userId
        TestingAuthenticationToken auth = new TestingAuthenticationToken(authenticatedUser, null);
        auth.setAuthenticated(true);
        return ReactiveSecurityContextHolder.withAuthentication(auth);
    }

    @Test
    void shouldApplyFilterWhenAuthenticatedAndEmployeeIdClaimPresent() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // When
        AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, mockChain)
                .contextWrite(authContextWithJwtClaim("employeeId", "original-employee-id")))
            .expectComplete()
            .verify();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
    }

    @Test
    void shouldApplyFilterAndOverrideValuesWhenAuthenticatedAndEmployeeIdClaimPresent() {
        // Given
        when(authorizationConfiguration.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test"));
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // When
        AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, mockChain)
                .contextWrite(authContextWithJwtClaim("employeeId", "original-employee-id")))
            .expectComplete()
            .verify();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getURI().getQuery()).contains("user=original-employee-id");
    }

    @Test
    void shouldNotApplyFilterWhenAuthenticatedButEmployeeIdClaimNull() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // When
        AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, mockChain)
                .contextWrite(authContextWithJwtClaim("employeeId", null)))
            .expectComplete()
            .verify();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().get("userId")).isNullOrEmpty();
        assertThat(mutatedRequest.getURI().getQuery()).doesNotContain("user=");
    }

    @Test
    void shouldNotApplyFilterWhenNotAuthenticated() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // When
        AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, mockChain))
            .expectComplete()
            .verify();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().get("userId")).isNullOrEmpty();
        assertThat(mutatedRequest.getURI().getQuery()).doesNotContain("user=");
    }

    @Test
    void shouldAddUserToQueryParams() {
        // Given
        when(authorizationConfiguration.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test"));
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // When
        AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, mockChain)
                .contextWrite(authContextWithJwtClaim("employeeId", "original-employee-id")))
            .expectComplete()
            .verify();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getURI().getQuery()).contains("user=original-employee-id");
    }

    // Metoda pomocnicza buildExchange
    private ServerWebExchange buildExchange(String bodyJson, String serviceId, HttpMethod method) {
        MockServerHttpRequest.Builder requestBuilder = MockServerHttpRequest.method(method, "/test");
        if (bodyJson != null) {
            requestBuilder.contentType(MediaType.APPLICATION_JSON).body(bodyJson.getBytes());
        }
        ServerWebExchange exchange = MockServerWebExchange.from(requestBuilder.build());
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, new Route(serviceId, URI.create("http://test")));
        return exchange;
    }
}
