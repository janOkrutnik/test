import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AddUserHeaderAndParamFilterTest {

    private AddUserHeaderAndParamFilter filter;
    private AuthorizationConfiguration mockAuthConfig;
    private Authentication mockAuth;
    private TestingAuthenticationToken mockToken;
    private AtomicReference<ServerWebExchange> capturedExchange;

    @BeforeEach
    void setUp() {
        // Mock AuthorizationConfiguration
        mockAuthConfig = mock(AuthorizationConfiguration.class);
        when(mockAuthConfig.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test")); // Domyślna konfiguracja
        filter = new AddUserHeaderAndParamFilter(mockAuthConfig);

        // Mock Authentication i Security Context
        mockAuth = mock(Authentication.class);
        mockToken = new TestingAuthenticationToken("user", "pass");
        mockToken.setDetails(new Jwt(Map.of("employeeId", "original-employee-id"))); // Domyślny claim
        when(mockAuth.getPrincipal()).thenReturn(mockToken);

        // Ustaw kontekst security
        ReactiveSecurityContextHolder.getContext().contextWrite(securityContext -> {
            securityContext.setAuthentication(mockAuth);
            return securityContext;
        });

        // Inicjalizacja capturedExchange dla mock chain
        capturedExchange = new AtomicReference<>();
    }

    private ServerWebExchange buildExchange(String bodyJson, String serviceId, HttpMethod method) {
        MockServerHttpRequest.Builder requestBuilder = MockServerHttpRequest.method(method, "/test");
        if (bodyJson != null) {
            requestBuilder.contentType(MediaType.APPLICATION_JSON).body(bodyJson.getBytes());
        }
        ServerWebExchange exchange = MockServerWebExchange.from(requestBuilder.build());
        exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, new Route(serviceId, URI.create("http://test")));
        return exchange;
    }

    @Test
    void shouldApplyFilterWhenAuthenticatedAndEmployeeIdClaimPresent() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // Mock chain
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        // When
        filter.filter(exchange, mockChain).block();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getHeaders().getFirst("user")).isEqualTo("original-employee-id");
    }

    @Test
    void shouldApplyFilterAndOverrideValuesWhenAuthenticatedAndEmployeeIdClaimPresent() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // Mock chain
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        // When
        filter.filter(exchange, mockChain).block();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getHeaders().getFirst("user")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getURI().getQuery()).contains("user=original-employee-id");
    }

    @Test
    void shouldNotApplyFilterWhenAuthenticatedButEmployeeIdClaimNull() {
        // Given
        mockToken.setDetails(new Jwt(new HashMap<>())); // Usuń employeeId
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // Mock chain
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        // When
        filter.filter(exchange, mockChain).block();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().get("userId")).isNullOrEmpty();
        assertThat(mutatedRequest.getHeaders().get("user")).isNullOrEmpty();
        assertThat(mutatedRequest.getURI().getQuery()).doesNotContain("user=");
    }

    @Test
    void shouldNotApplyFilterWhenNotAuthenticated() {
        // Given
        ReactiveSecurityContextHolder.resetContext(); // Wyczyść kontekst
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // Mock chain
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        // When
        filter.filter(exchange, mockChain).block();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().get("userId")).isNullOrEmpty();
        assertThat(mutatedRequest.getHeaders().get("user")).isNullOrEmpty();
        assertThat(mutatedRequest.getURI().getQuery()).doesNotContain("user=");
    }

    @Test
    void shouldAddUserToQueryParams() {
        // Given
        ServerWebExchange exchange = buildExchange(null, "service-test", HttpMethod.GET);

        // Mock chain
        GatewayFilterChain mockChain = mutatedExchange -> {
            capturedExchange.set(mutatedExchange);
            return Mono.empty();
        };

        // When
        filter.filter(exchange, mockChain).block();

        // Then
        ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
        assertThat(mutatedRequest.getHeaders().getFirst("userId")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getHeaders().getFirst("user")).isEqualTo("original-employee-id");
        assertThat(mutatedRequest.getURI().getQuery()).contains("user=original-employee-id");
    }
}
