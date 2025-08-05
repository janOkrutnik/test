package com.hsbc.cmva.scp.api.gateway.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.TestSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeUtils;
import reactor.core.publisher.Context;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AddUserHeaderAndParamFilterTest {

    private AddUserHeaderAndParamFilter filter;
    private AuthorizationConfiguration mockAuthConfig;

    @BeforeEach
    void setUp() {
        mockAuthConfig = mock(AuthorizationConfiguration.class);
        filter = new AddUserHeaderAndParamFilter(mockAuthConfig);
    }

    // Metoda authContextWithJwtClaim jak w Twoim przykładzie
    private Context authContextWithJwtClaim(String claimKey, String claimValue) {
        Jwt jwt = mock(Jwt.class);
        when(jwt.getClaimAsString(claimKey)).thenReturn(claimValue);
        TestingAuthenticationToken auth = new TestingAuthenticationToken(jwt, null);
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
        when(mockAuthConfig.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test"));
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
        when(mockAuthConfig.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test"));
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
