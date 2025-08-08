void shouldNotApplyFilterWhenServiceEligibleForOverrideAndAuthenticatedButNotAuthorized() {
    // Arrange: Eligible service, authenticated, but not authorized (user lacks required authorities)
    MockServerHttpRequest request = MockServerHttpRequest.get("/test").build();
    exchange = MockServerWebExchange.from(request);

    // Mock Route with serviceId
    Route route = mock(Route.class);
    when(route.getId()).thenReturn("some-service-id");
    exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, route);

    // Mock config: Eligible service with required authorities
    AuthorizationConfiguration.BasicAuthService basicAuthService = mock(AuthorizationConfiguration.BasicAuthService.class);
    when(basicAuthService.getRequiredAuthorities()).thenReturn(Set.of("ROLE_ADMIN")); // Required, user will not have it

    Map<String, AuthorizationConfiguration.BasicAuthService> basicAuthServices = Map.of("some-service-id", basicAuthService);
    when(authorizationConfiguration.getBasicAuthServices()).thenReturn(basicAuthServices);

    // Mock authenticated but unauthorized user (JWT with empty authorities in claims)
    Map<String, Object> claims = Map.of("authorities", List.of()); // Empty authorities in claims
    Jwt jwt = new Jwt("token-value", Instant.now(), Instant.now().plusSeconds(3600), Map.of("alg", "none"), claims);

    // Authorities can be derived from claims, but for test, set empty
    Collection<GrantedAuthority> authorities = Collections.emptyList();

    // Create JwtAuthenticationToken (public constructor)
    JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt, authorities);

    // Set up SecurityContext
    SecurityContext securityContext = mock(SecurityContext.class);
    when(securityContext.getAuthentication()).thenReturn(auth);
    // Assuming your mockSecurityContext or helper sets ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext))

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    assert exchange.getResponse().getStatusCode() == HttpStatus.FORBIDDEN;
    assert exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null;

    verify(chain, never()).filter(any()); // Should pass, as blocked
}
