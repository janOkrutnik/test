@Test
void shouldApplyFilterWhenAuthenticatedAndEmployeeIdClaimPresent() {
    // Given
    AuthorizationConfiguration mockAuthConfig = mock(AuthorizationConfiguration.class);
    AddUserHeaderAndParamFilter filter = new AddUserHeaderAndParamFilter(mockAuthConfig);

    ServerHttpRequest mockRequest = MockServerHttpRequest.get("/test").build();
    ServerWebExchange exchange = MockServerWebExchange.from(mockRequest);

    Authentication mockAuth = mock(Authentication.class);
    TestingAuthenticationToken mockToken = new TestingAuthenticationToken("user", "pass");
    mockToken.setDetails(new Jwt(Map.of("employeeId", "original-employee-id")));
    when(mockAuth.getPrincipal()).thenReturn(mockToken);

    ReactiveSecurityContextHolder.getContext().contextWrite(securityContext -> {
        securityContext.setAuthentication(mockAuth);
        return securityContext;
    });

    // Mock chain to capture mutated exchange
    AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
    GatewayFilterChain mockChain = mutatedExchange -> {
        capturedExchange.set(mutatedExchange);
        return Mono.empty();
    };

    // When
    filter.filter(exchange, mockChain).block();

    // Then
    ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
    assertThat(mutatedRequest.getHeaders().getFirst("user")).isEqualTo("original-employee-id");
}



@Test
void shouldApplyFilterAndOverrideValuesWhenAuthenticatedAndEmployeeIdClaimPresent() {
    // Given
    AuthorizationConfiguration mockAuthConfig = mock(AuthorizationConfiguration.class);
    when(mockAuthConfig.getServicesToAddUserAsQueryParam()).thenReturn(Set.of("service-test"));
    AddUserHeaderAndParamFilter filter = new AddUserHeaderAndParamFilter(mockAuthConfig);

    ServerHttpRequest mockRequest = MockServerHttpRequest.get("/test?user=old-value").build();
    ServerWebExchange exchange = MockServerWebExchange.from(mockRequest);
    exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, new Route("service-test", URI.create("lb://service-test")));

    Authentication mockAuth = mock(Authentication.class);
    TestingAuthenticationToken mockToken = new TestingAuthenticationToken("user", "pass");
    mockToken.setDetails(new Jwt(Map.of("employeeId", "original-employee-id")));
    when(mockAuth.getPrincipal()).thenReturn(mockToken);

    ReactiveSecurityContextHolder.getContext().contextWrite(securityContext -> {
        securityContext.setAuthentication(mockAuth);
        return securityContext;
    });

    // Mock chain to capture mutated exchange
    AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
    GatewayFilterChain mockChain = mutatedExchange -> {
        capturedExchange.set(mutatedExchange);
        return Mono.empty();
    };

    // When
    filter.filter(exchange, mockChain).block();

    // Then
    ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
    assertThat(mutatedRequest.getHeaders().getFirst("user")).isEqualTo("original-employee-id");
    assertThat(mutatedRequest.getURI().getQuery()).contains("user=original-employee-id");  // Nadpisuje old-value
}




@Test
void shouldNotApplyFilterWhenAuthenticatedButEmployeeIdClaimNull() {
    // Given
    AuthorizationConfiguration mockAuthConfig = mock(AuthorizationConfiguration.class);
    AddUserHeaderAndParamFilter filter = new AddUserHeaderAndParamFilter(mockAuthConfig);

    ServerHttpRequest mockRequest = MockServerHttpRequest.get("/test").build();
    ServerWebExchange exchange = MockServerWebExchange.from(mockRequest);

    Authentication mockAuth = mock(Authentication.class);
    TestingAuthenticationToken mockToken = new TestingAuthenticationToken("user", "pass");
    mockToken.setDetails(new Jwt(Map.of()));  // Brak employeeId
    when(mockAuth.getPrincipal()).thenReturn(mockToken);

    ReactiveSecurityContextHolder.getContext().contextWrite(securityContext -> {
        securityContext.setAuthentication(mockAuth);
        return securityContext;
    });

    // Mock chain to capture mutated exchange
    AtomicReference<ServerWebExchange> capturedExchange = new AtomicReference<>();
    GatewayFilterChain mockChain = mutatedExchange -> {
        capturedExchange.set(mutatedExchange);
        return Mono.empty();
    };

    // When
    filter.filter(exchange, mockChain).block();

    // Then
    ServerHttpRequest mutatedRequest = capturedExchange.get().getRequest();
    assertThat(mutatedRequest.getHeaders().get("user")).isNullOrEmpty();
    assertThat(mutatedRequest.getURI().getQuery()).doesNotContain("user=");
}
