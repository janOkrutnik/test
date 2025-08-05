@Override
public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    log.info("Start AddUserHeaderAndParamFilter for {}", exchange.getRequest().getURI());

    return ReactiveSecurityContextHolder.getContext()
        .map(securityContext -> {
            Authentication authentication = securityContext.getAuthentication();
            if (authentication == null || authentication.getPrincipal() == null) {
                log.info("No security context or authentication found, passing through.");
                return exchange;  // Zwróć oryginalny exchange
            }

            Object principal = authentication.getPrincipal();
            log.info("Principal class: {}", principal.getClass().getName());

            if (!(principal instanceof AuthenticatedUser)) {
                log.info("Principal is not AuthenticatedUser, passing through.");
                return exchange;  // Zwróć oryginalny
            }

            AuthenticatedUser authenticatedUser = (AuthenticatedUser) principal;
            String userId = authenticatedUser.getUserId();
            log.info("Authenticated userId: {}", userId);

            if (!StringUtils.hasText(userId)) {
                log.debug("userId is null or empty, passing through.");
                return exchange;  // Zwróć oryginalny
            }

            // Logika mutacji exchange (dodanie headera i ewentualnie query param)
            ServerHttpRequest request = exchange.getRequest();
            String serviceId = extractServiceId(exchange);
            ServerHttpRequest.Builder mutatedBuilder = request.mutate()
                .header("user", userId);

            if (serviceId != null && authorizationConfiguration.getServicesToAddUserAsQueryParams().contains(serviceId)) {
                URI originalUri = request.getURI();
                String query = originalUri.getQuery();

                // Lepsza sprawdzenie query param (zamiast regex – użyj UriComponents)
                MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUri(originalUri).build().getQueryParams();
                if (!queryParams.containsKey("user")) {
                    log.info("Added user as query param for serviceId {}", serviceId);
                    URI newUri = UriComponentsBuilder.fromUri(originalUri)
                        .queryParam("user", userId)
                        .build().toUri();
                    mutatedBuilder.uri(newUri);
                } else {
                    log.info("Query param 'user' already exists, not adding for serviceId {}", serviceId);
                }
            }

            ServerHttpRequest mutatedRequest = mutatedBuilder.build();
            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
            log.debug("Passing mutated exchange to chain.filter()");

            return mutatedExchange;  // Zwróć zmodyfikowany exchange
        })
        .defaultIfEmpty(exchange)  // Jeśli Mono jest puste (brak kontekstu), użyj oryginalnego
        .flatMap(modifiedExchange -> chain.filter(modifiedExchange));  // Zawsze wywołaj chain na (ew. zmodyfikowanym) exchange
}
