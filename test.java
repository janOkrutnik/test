import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;
import static org.springframework.http.HttpMethod.GET;

@ExtendWith(MockitoExtension.class)
class AddUserHeaderAndParamFilterTest {

    @Mock
    private AuthorizationConfiguration authorizationConfiguration;

    @InjectMocks
    private AddUserHeaderAndParamFilter filter;

    @Mock
    private GatewayFilterChain chain;

    private ServerWebExchange exchange;

    @BeforeEach
    void setUp() {
        exchange = MockServerWebExchange.from(MockServerWebExchange.builder()
                .method(GET)
                .url(UriComponentsBuilder.fromUriString("http://example.com").build().toUri())
                .build());
    }

    @Test
    void shouldNotModifyRequestWhenNoAuthentication() {
        // Arrange: Brak kontekstu uwierzytelniania
        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Brak dodanych nagłówków ani parametrów
        verify(chain).filter(exchange); // Oryginalne exchange bez zmian
        assert exchange.getRequest().getHeaders().get("userId") == null;
        assert exchange.getRequest().getHeaders().get("user") == null;
    }

    @Test
    void shouldAddHeadersWhenAuthenticated() {
        // Arrange: Uwierzytelniony użytkownik
        String userId = "test-user-123";
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getUserId()).thenReturn(userId);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(authenticatedUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        // Symulacja ReactiveSecurityContextHolder
        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Dodane nagłówki
        assert exchange.getRequest().getHeaders().getFirst("userId").equals(userId);
        assert exchange.getRequest().getHeaders().getFirst("user").equals(userId);
    }

    @Test
    void shouldAddQueryParamWhenServiceIdRequiresItAndParamMissing() {
        // Arrange: Uwierzytelniony użytkownik, serviceId na liście
        String userId = "test-user-123";
        String serviceId = "required-service";
        Set<String> services = new HashSet<>(Collections.singletonList(serviceId));
        when(authorizationConfiguration.getServicesToAddUserAsQueryParams()).thenReturn(services);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getUserId()).thenReturn(userId);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(authenticatedUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));

        // Ustaw route z serviceId
        Route route = mock(Route.class);
        when(route.getId()).thenReturn(serviceId);
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Dodany parametr zapytania "user"
        String updatedUri = exchange.getRequest().getURI().toString();
        assert updatedUri.contains("user=" + userId);
    }

    @Test
    void shouldNotAddQueryParamWhenServiceIdNotRequiresIt() {
        // Arrange: Uwierzytelniony użytkownik, ale serviceId nie na liście
        String userId = "test-user-123";
        String serviceId = "not-required-service";
        when(authorizationConfiguration.getServicesToAddUserAsQueryParams()).thenReturn(new HashSet<>()); // Pusta lista

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getUserId()).thenReturn(userId);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(authenticatedUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));

        Route route = mock(Route.class);
        when(route.getId()).thenReturn(serviceId);
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Brak parametru zapytania
        String updatedUri = exchange.getRequest().getURI().toString();
        assert !updatedUri.contains("user=");
    }

    @Test
    void shouldNotAddQueryParamWhenAlreadyExists() {
        // Arrange: Uwierzytelniony użytkownik, serviceId na liście, ale parametr już istnieje
        String userId = "test-user-123";
        String serviceId = "required-service";
        Set<String> services = new HashSet<>(Collections.singletonList(serviceId));
        when(authorizationConfiguration.getServicesToAddUserAsQueryParams()).thenReturn(services);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getUserId()).thenReturn(userId);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(authenticatedUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));

        Route route = mock(Route.class);
        when(route.getId()).thenReturn(serviceId);
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        // Symulacja istniejącego parametru
        exchange = MockServerWebExchange.from(MockServerWebExchange.builder()
                .method(GET)
                .url(UriComponentsBuilder.fromUriString("http://example.com?user=existing").build().toUri())
                .build());

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Parametr nie nadpisany
        String updatedUri = exchange.getRequest().getURI().toString();
        assert updatedUri.contains("user=existing"); // Zachowany oryginalny
        assert !updatedUri.contains("user=" + userId); // Nie dodany nowy
    }

    @Test
    void shouldHandleNullServiceIdGracefully() {
        // Arrange: Uwierzytelniony użytkownik, ale brak route/serviceId
        String userId = "test-user-123";
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getUserId()).thenReturn(userId);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(authenticatedUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext));

        // Brak GATEWAY_ROUTE_ATTR
        exchange.getAttributes().remove(GATEWAY_ROUTE_ATTR);

        when(chain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Act & Assert
        StepVerifier.create(filter.filter(exchange, chain))
                .verifyComplete();

        // Weryfikacja: Dodane nagłówki, ale brak parametru (bo null serviceId)
        assert exchange.getRequest().getHeaders().getFirst("userId").equals(userId);
        assert exchange.getRequest().getHeaders().getFirst("user").equals(userId);
        String updatedUri = exchange.getRequest().getURI().toString();
        assert !updatedUri.contains("user=");
    }
}
