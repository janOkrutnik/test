package com.example.solace;

import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.TextMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicInteger;

@Component
public class NotificationHandler {

    private static final Logger log = LoggerFactory.getLogger(NotificationHandler.class);
    private final AtomicInteger messageCount = new AtomicInteger(0);

    @JmsListener(destination = "notifications-queue")
    public void onNotification(Message message) throws JMSException {
        String text = (message instanceof TextMessage tm) ? tm.getText() : message.toString();
        log.info("wow - notification: {}", text);
        messageCount.incrementAndGet();
    }

    public int getMessageCount() {
        return messageCount.get();
    }
}
