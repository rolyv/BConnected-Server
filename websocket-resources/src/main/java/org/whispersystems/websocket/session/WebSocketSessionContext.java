/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.websocket.session;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;
import org.whispersystems.websocket.WebSocketClient;

public class WebSocketSessionContext {

  private final List<WebSocketEventListener> closeListeners = new LinkedList<>();

  private final ReentrantLock lock = new ReentrantLock();

  private final WebSocketClient webSocketClient;

  private volatile Object authenticated;
  private boolean closed;

  public WebSocketSessionContext(WebSocketClient webSocketClient) {
    this.webSocketClient = webSocketClient;
  }

  public void setAuthenticated(Object authenticated) {
    this.authenticated = authenticated;
  }

  public <T> T getAuthenticated(Class<T> clazz) {
    final Object current = authenticated;
    if (current != null && clazz.equals(current.getClass())) {
      return clazz.cast(current);
    }

    throw new IllegalArgumentException("No authenticated type for: " + clazz + ", we have: " + authenticated);
  }

  @Nullable
  public Object getAuthenticated() {
    return authenticated;
  }

  public void addWebsocketClosedListener(WebSocketEventListener listener) {
    final boolean alreadyClosed;
    lock.lock();
    try {
      alreadyClosed = closed;
      if (!alreadyClosed)
        this.closeListeners.add(listener);
    } finally {
      lock.unlock();
    }
    if (alreadyClosed) listener.onWebSocketClose(this, 1000, "Closed");
  }

  public WebSocketClient getClient() {
    return webSocketClient;
  }

  public void notifyClosed(int statusCode, String reason) {
    final List<WebSocketEventListener> listeners;
    lock.lock();
    try {
      if (closed) return;
      closed = true;
      listeners = List.copyOf(closeListeners);
      closeListeners.clear();
    } finally {
      lock.unlock();
    }
    // Listeners may acquire their own lifecycle locks or register further listeners. Never hold
    // the context lock while invoking them, and expose closed state before callbacks begin.
    listeners.forEach(listener -> listener.onWebSocketClose(this, statusCode, reason));
  }

  public interface WebSocketEventListener {
    void onWebSocketClose(WebSocketSessionContext context, int statusCode, String reason);
  }


}
