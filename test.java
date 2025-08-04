import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;

@Component
@Order(100)  // Analogicznie do filterOrder w Zuul
public class AddUserHeaderAndParamFilter implements GlobalFilter {

    private final AuthorizationConfiguration authorizationConfiguration;

    public AddUserHeaderAndParamFilter(AuthorizationConfiguration authorizationConfiguration) {
        this.authorizationConfiguration = authorizationConfiguration;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
            .map(securityContext -> (AuthenticatedUser) securityContext.getAuthentication().getPrincipal())
            .defaultIfEmpty(null)
            .flatMap(authenticatedUser -> {
                String userId = (authenticatedUser != null) ? authenticatedUser.getUserId() : null;

                if (userId == null || !StringUtils.hasText(userId)) {
                    // Skip jeśli brak userId (analogicznie do shouldFilter w Zuul)
                    return chain.filter(exchange);
                }

                ServerHttpRequest request = exchange.getRequest();
                String serviceId = extractServiceId(exchange);  // Zakładam, że masz metodę jak w poprzednich filtrach

                // Buduj mutated request
                ServerHttpRequest.Builder mutatedRequestBuilder = request.mutate();

                // Dodaj header "user"
                mutatedRequestBuilder.header("user", userId);

                // Dodaj query param "user" jeśli serviceId w konfiguracji
                if (serviceId != null && authorizationConfiguration.getServicesToAddUserAsQueryParam().contains(serviceId)) {
                    URI originalUri = request.getURI();
                    URI newUri = UriComponentsBuilder.fromUri(originalUri)
                        .queryParam("user", userId)
                        .build().toUri();
                    mutatedRequestBuilder.uri(newUri);
                }

                // Zbuduj nowy exchange z mutated request
                ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(mutatedRequestBuilder.build())
                    .build();

                return chain.filter(mutatedExchange);
            });
    }

    // Metoda pomocnicza do extract serviceId (jak w poprzednich kodach)
    private String extractServiceId(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return (route != null) ? route.getId() : null;  // Lub dostosuj do Twojego sposobu pobierania
    }
}
