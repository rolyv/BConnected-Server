// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.websocket.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.whispersystems.websocket.WebSocketClient;

class WebSocketSessionContextTest {
  @Test
  void closureIsIdempotentAndReentrantListenersSeeClosedState() {
    var context = new WebSocketSessionContext(mock(WebSocketClient.class));
    AtomicInteger first = new AtomicInteger(), late = new AtomicInteger();
    context.addWebsocketClosedListener((ctx, code, reason) -> {
      first.incrementAndGet();
      ctx.addWebsocketClosedListener((_, _, _) -> late.incrementAndGet());
      ctx.notifyClosed(code, reason);
    });
    context.notifyClosed(1000, "test");
    context.notifyClosed(1000, "test");
    assertThat(first.get()).isEqualTo(1);
    assertThat(late.get()).isEqualTo(1);
  }

  @Test
  void closeCallbackDoesNotBlockConcurrentLateListenerOnContextLock() throws Exception {
    var context = new WebSocketSessionContext(mock(WebSocketClient.class));
    var started = new CountDownLatch(1);
    var late = new CountDownLatch(1);
    context.addWebsocketClosedListener((_, _, _) -> {
      started.countDown();
      try { assertThat(late.await(3, TimeUnit.SECONDS)).isTrue(); }
      catch (InterruptedException e) { throw new AssertionError(e); }
    });
    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      var close = executor.submit(() -> context.notifyClosed(1000, "test"));
      assertThat(started.await(3, TimeUnit.SECONDS)).isTrue();
      var registration = executor.submit(() -> context.addWebsocketClosedListener((_, _, _) -> late.countDown()));
      registration.get(3, TimeUnit.SECONDS);
      close.get(3, TimeUnit.SECONDS);
    }
  }
}
