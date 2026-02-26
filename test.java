package com.example.solace;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@Testcontainers
class SolaceIntegrationTest {

    private static final int SMF_PORT = 55555;
    private static final int SEMP_PORT = 8080;
    private static final int HEALTH_CHECK_PORT = 5550;

    @Container
    static GenericContainer<?> solace = new GenericContainer<>(
            DockerImageName.parse("solace/solace-pubsub-standard:latest"))
        .withExposedPorts(SMF_PORT, SEMP_PORT, HEALTH_CHECK_PORT)
        .withEnv("username_admin_globalaccesslevel", "admin")
        .withEnv("username_admin_password", "admin")
        .withSharedMemorySize(1024L * 1024L * 1024L)
        .waitingFor(Wait.forHttp("/health-check/guaranteed-active")
            .forPort(HEALTH_CHECK_PORT)
            .forStatusCode(200)
            .withStartupTimeout(Duration.ofSeconds(300)));

    @DynamicPropertySource
    static void solaceProperties(DynamicPropertyRegistry registry) {
        provisionQueue("orders-queue");
        provisionQueue("notifications-queue");

        registry.add("solace.jms.host", () ->
            String.format("smf://%s:%d", solace.getHost(), solace.getMappedPort(SMF_PORT)));
        registry.add("solace.jms.msgVpn", () -> "default");
        registry.add("solace.jms.clientUsername", () -> "default");
        registry.add("solace.jms.clientPassword", () -> "default");
    }

    private static void provisionQueue(String queueName) {
        String sempUrl = String.format("http://%s:%d/SEMP/v2/config/msgVpns/default/queues",
            solace.getHost(), solace.getMappedPort(SEMP_PORT));

        String body = String.format("""
            {
                "queueName": "%s",
                "accessType": "exclusive",
                "permission": "consume",
                "ingressEnabled": true,
                "egressEnabled": true
            }""", queueName);

        String auth = Base64.getEncoder().encodeToString("admin:admin".getBytes());

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(sempUrl))
                .header("Content-Type", "application/json")
                .header("Authorization", "Basic " + auth)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to provision queue " + queueName
                    + ": HTTP " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to provision queue " + queueName, e);
        }
    }

    @Autowired
    private JmsTemplate jmsTemplate;

    @Autowired
    private OrderHandler orderHandler;

    @Autowired
    private NotificationHandler notificationHandler;

    @Test
    void shouldReceiveOrderMessage() {
        jmsTemplate.convertAndSend("orders-queue", "Order #123");

        await().atMost(Duration.ofSeconds(10))
            .untilAsserted(() -> assertThat(orderHandler.getMessageCount()).isPositive());
    }

    @Test
    void shouldReceiveNotificationMessage() {
        jmsTemplate.convertAndSend("notifications-queue", "You have a new alert!");

        await().atMost(Duration.ofSeconds(10))
            .untilAsserted(() -> assertThat(notificationHandler.getMessageCount()).isPositive());
    }
}
