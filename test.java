oid shouldNotApplyFilterWhenServiceEligibleForOverrideAndAuthenticatedButNotAuthorized() {
    // Arrange: Eligible service, authenticated, but not authorized (user lacks required authorities)
    ServerHttpRequest request = MockServerHttpRequest.get("/test").build();
    exchange = MockServerWebExchange.from(request);
    exchange.getAttributes().put(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR, new Route("id", URI.create("http://some-service")));

    // Mock config: Eligible service with required authorities
    AuthorizationConfiguration.BasicAuthService basicAuthService = mock(AuthorizationConfiguration.BasicAuthService.class);
    when(basicAuthService.getBasicAuthorizationHeader()).thenReturn("Basic dXNlcjpwYXNz"); // Not used in this path, but for completeness
    when(basicAuthService.getRequiredAuthorities()).thenReturn(Set.of("ROLE_ADMIN")); // Required, user will not have it

    Map<String, AuthorizationConfiguration.BasicAuthService> basicAuthServices = Map.of("some-service-id", basicAuthService);
    when(authorizationConfiguration.getBasicAuthServices()).thenReturn(basicAuthServices);

    // Mock authenticated but unauthorized user (JWT with empty authorities)
    Map<String, Object> claims = Map.of("authorities", List.of()); // Empty authorities
    Jwt jwt = new Jwt("token-value", Instant.now(), Instant.now().plusSeconds(3600), Map.of("alg", "none"), claims);
    
    Collection<GrantedAuthority> authorities = Collections.emptyList(); // Not used directly, but for token
    OAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(jwt.getClaims(), authorities);
    OAuth2AuthenticationToken auth = new OAuth2AuthenticationToken(principal, authorities, "registration-id");
    
    mockSecurityContext(auth); // Assuming your helper sets ReactiveSecurityContextHolder.withAuthentication(auth)

    // Act
    Mono<Void> result = filter.filter(exchange, chain);

    // Assert
    StepVerifier.create(result).verifyComplete();
    
    assert exchange.getResponse().getStatusCode() == HttpStatus.FORBIDDEN;
    assert exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null; // No header added
    
    verify(chain, never()).filter(any()); // Now should pass, as blocked
}
