// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import io.dropwizard.auth.Auth;
import io.dropwizard.auth.basic.BasicCredentials;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.ApplicationHandler;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.AuthenticationUnavailableException;
import org.whispersystems.textsecuregcm.websocket.AdmissionWebSocketRequestFilter;
import org.whispersystems.textsecuregcm.websocket.AdmissionWebSocketSessionManager;
import org.whispersystems.websocket.WebSocketClient;
import org.whispersystems.websocket.WebSocketResourceProvider;
import org.whispersystems.websocket.WebSocketSecurityContext;
import org.whispersystems.websocket.auth.WebsocketAuthValueFactoryProvider;
import org.whispersystems.websocket.session.ContextPrincipal;
import org.whispersystems.websocket.session.WebSocketSessionContext;

/** Real local PostgreSQL and actual Jersey dispatch; all issuer responses and socket IO are synthetic. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionWebSocketPostgresTest {
  AdmissionEntitlementGatePostgresTest fixture;
  AdmissionWebSocketSessionManager sessions;
  ScheduledExecutorService scheduler;
  final List<Scheduled> timers = new ArrayList<>();
  final Queue<Runnable> workers = new ConcurrentLinkedQueue<>();
  WebSocketClient socket;
  WebSocketSessionContext context;
  AuthenticatedDevice initial;
  Probe probe;
  ApplicationHandler jersey;
  AtomicInteger connects = new AtomicInteger();
  ManagedExecutor managed = new ManagedExecutor();

  record Scheduled(long due, FutureTask<Void> task) {}

  @BeforeEach
  void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest();
    fixture.setup();
    scheduler = mock(ScheduledExecutorService.class);
    when(scheduler.schedule(any(Runnable.class), anyLong(), any(TimeUnit.class))).thenAnswer(call -> {
      Runnable command = call.getArgument(0);
      long delay = call.getArgument(1);
      TimeUnit unit = call.getArgument(2);
      var task = new FutureTask<Void>(command, null);
      timers.add(new Scheduled(fixture.flow.http.nanos.get() + unit.toNanos(delay), task));
      var handle = mock(ScheduledFuture.class);
      when(handle.cancel(anyBoolean())).thenAnswer(cancel -> task.cancel(cancel.getArgument(0)));
      return handle;
    });
    sessions = new AdmissionWebSocketSessionManager(scheduler, workers::add);
    socket = mock(WebSocketClient.class);
    when(socket.isOpen()).thenReturn(true);
    context = new WebSocketSessionContext(socket);
    initial = principal(fixture.gate);
    context.setAuthenticated(initial);
    probe = new Probe();
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new AdmissionWebSocketRequestFilter(sessions))
        .register(new WebsocketAuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .register(managed)
        .register(probe));
  }

  AuthenticatedDevice principal(AdmissionEntitlementGate gate) {
    return AccountAuthenticator.withAdmission(gate).authenticate(new BasicCredentials(
        fixture.aci.toString(), fixture.flow.input.password())).orElseThrow();
  }

  @AfterEach
  void cleanup() throws Exception {
    if (sessions != null) sessions.stop();
    if (fixture != null) fixture.close();
  }

  void connect() {
    sessions.wrap(ignored -> connects.incrementAndGet()).onWebSocketConnect(context);
  }

  void advance(long millis) {
    fixture.flow.http.advance(millis);
    runTimers();
  }

  void runTimers() {
    while (true) {
      var next = timers.stream().filter(t -> !t.task().isDone()
          && t.due() <= fixture.flow.http.nanos.get()).min(Comparator.comparingLong(Scheduled::due));
      if (next.isEmpty()) return;
      next.get().task().run();
    }
  }

  void runRenewal() { Objects.requireNonNull(workers.poll()).run(); }

  int request() throws Exception {
    return requestFuture("/probe").get(5, TimeUnit.SECONDS).getStatus();
  }

  Future<org.glassfish.jersey.server.ContainerResponse> requestFuture(String path) {
    var request = new ContainerRequest(URI.create("http://localhost/"), URI.create("http://localhost" + path),
        "GET", new WebSocketSecurityContext(new ContextPrincipal(context)), new MapPropertiesDelegate(), null);
    request.setProperty(WebSocketResourceProvider.REUSABLE_AUTH_PROPERTY, Optional.of(initial));
    return jersey.apply(request);
  }

  @Path("/probe")
  public static class Probe {
    int calls;
    AuthenticatedDevice received;
    @GET public String read(@Auth Optional<AuthenticatedDevice> principal, @Context SecurityContext security) {
      calls++;
      received = principal.orElseThrow();
      assertThat(security.getUserPrincipal()).isSameAs(received);
      return "ok";
    }
    @GET @Path("/async") @org.glassfish.jersey.server.ManagedAsync
    public String async() {
      calls++;
      return "ok"; // No @Auth parameter: the method-dispatch security hook still must run.
    }
  }

  @org.glassfish.jersey.server.ManagedAsyncExecutor
  public static class ManagedExecutor implements org.glassfish.jersey.spi.ExecutorServiceProvider {
    final Queue<Runnable> queued = new ConcurrentLinkedQueue<>();
    final ExecutorService executor = new AbstractExecutorService() {
      boolean stopped;
      @Override public void shutdown() { stopped = true; }
      @Override public List<Runnable> shutdownNow() { stopped = true; return List.copyOf(queued); }
      @Override public boolean isShutdown() { return stopped; }
      @Override public boolean isTerminated() { return stopped; }
      @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return stopped; }
      @Override public void execute(Runnable command) { queued.add(command); }
    };
    @Override public ExecutorService getExecutorService() { return executor; }
    @Override public void dispose(ExecutorService service) { service.shutdown(); }
  }

  @Test
  void actualOptionalAuthHandlerRequiresManagedProof() throws Exception {
    assertThat(request()).isEqualTo(401);
    assertThat(probe.calls).isZero();
    connect();
    assertThat(connects.get()).isEqualTo(1);
    assertThat(request()).isEqualTo(200);
    assertThat(probe.received).isSameAs(initial);
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void repeatedRenewalSurvivesOriginalFourSecondsAndReplacesOriginalInjectionProperty() throws Exception {
    connect();
    for (int i = 0; i < 5; i++) {
      advance(2000);
      assertThat(workers).hasSize(1);
      runRenewal();
      assertThat(request()).isEqualTo(200);
    }
    assertThat(fixture.requests.get()).isEqualTo(6);
    assertThat(probe.received).isNotSameAs(initial);
    assertThat(probe.received).isSameAs(context.getAuthenticated());
    assertThat(initial.admissionAuthorization().remainingNanos()).isZero();
    verify(socket, never()).close(anyInt(), anyString());
  }

  @Test
  void delayedWorkerCannotReopenExpiredConnectionAndDeadlineDoesNotNeedWorker() throws Exception {
    connect();
    advance(2000);
    assertThat(workers).hasSize(1);
    advance(2000);
    verify(socket).close(eq(1013), anyString());
    assertThat(request()).isEqualTo(503);
    runRenewal();
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThat(context.getAuthenticated()).isSameAs(initial);
    advance(250);
    verify(socket).disconnect();
    assertThat(probe.calls).isZero();
  }

  @Test
  void stoppedDeadlineSchedulerCannotAllowExpiredRequest() throws Exception {
    connect();
    fixture.flow.http.advance(4000); // Do not run even the renewal timer.
    assertThat(request()).isEqualTo(503);
    assertThat(probe.calls).isZero();
    verify(socket).close(eq(1013), anyString());
    assertThat(context.getAuthenticated()).isSameAs(initial); // Never downgrade to anonymous.
  }

  @ParameterizedTest
  @ValueSource(strings = {"UPDATE signal.accounts SET version=version+1",
      "UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!locked\"')",
      "DELETE FROM signal.accounts"})
  void changedIdentityBeforeRenewalCannotAdoptNewSnapshot(String mutation) {
    connect();
    fixture.sql(mutation);
    advance(2000);
    runRenewal();
    assertThat(fixture.requests.get()).isEqualTo(1);
    verify(socket).close(anyInt(), anyString());
    assertThat(context.getAuthenticated()).isSameAs(initial);
  }

  @Test
  void localSuspensionDeniesRequestBeforeHandler() throws Exception {
    connect();
    fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
    assertThat(request()).isEqualTo(401);
    assertThat(probe.calls).isZero();
    verify(socket).close(eq(1008), anyString());
  }

  @Test
  void localMutationDuringRenewalHttpClosesWithoutPublishing() {
    connect();
    fixture.duringHttp = () -> fixture.sql("UPDATE signal.accounts SET version=version+1");
    advance(2000);
    runRenewal();
    verify(socket).close(eq(1013), anyString());
    assertThat(context.getAuthenticated()).isSameAs(initial);
    assertThat(fixture.requests.get()).isEqualTo(2);
  }

  @ParameterizedTest
  @ValueSource(ints = {403, 429, 503})
  void issuerDenialOrOutageClosesWithoutPublishing(int status) {
    connect();
    fixture.httpStatus = status;
    advance(2000);
    runRenewal();
    verify(socket).close(eq(1013), anyString());
    assertThat(context.getAuthenticated()).isSameAs(initial);
  }

  @Test
  void oldLeaseExpiryDuringSuccessfulRenewalCannotBeReplacedByFreshResponse() {
    connect();
    fixture.duringHttp = () -> fixture.flow.http.advance(2000);
    advance(2000);
    runRenewal();
    verify(socket).close(eq(1013), anyString());
    assertThat(context.getAuthenticated()).isSameAs(initial);
    assertThat(fixture.requests.get()).isEqualTo(2);
  }

  @Test
  void renewalReceiptKeepsRequestStartBudgetAfterSlowHttp() throws Exception {
    connect();
    fixture.duringHttp = () -> fixture.flow.http.advance(1000);
    advance(2000);
    runRenewal();
    var current = context.getAuthenticated(AuthenticatedDevice.class);
    assertThat(current.admissionAuthorization().remainingNanos()).isEqualTo(TimeUnit.SECONDS.toNanos(3));
    assertThat(request()).isEqualTo(200);
    verify(socket, never()).close(anyInt(), anyString());
  }

  @Test
  void peerCloseFencesRenewalAlreadyInFlight() {
    connect();
    fixture.duringHttp = () -> context.notifyClosed(1000, "fixture closed");
    advance(2000);
    runRenewal();
    assertThat(context.getAuthenticated()).isSameAs(initial);
    assertThrows(AuthenticationUnavailableException.class, () -> sessions.requireCurrent(context));
  }

  @Test
  void noManagedConnectionCanBeDowngradedToAnonymousOrAnotherPrincipal() throws Exception {
    connect();
    context.setAuthenticated(null);
    assertThat(request()).isEqualTo(503);
    assertThat(probe.calls).isZero();
    verify(socket).close(eq(1013), anyString());
  }

  @Test
  void initialProoflessConnectionNeverReachesConnectDelegate() {
    context.setAuthenticated(new AuthenticatedDevice(fixture.aci, (byte) 1, Instant.EPOCH));
    connect();
    assertThat(connects.get()).isZero();
    verify(socket).close(eq(1008), anyString());
    assertThat(workers).isEmpty();
  }

  @Test
  void initialAnonymousConnectionNeverReachesConnectDelegate() {
    context.setAuthenticated(null);
    connect();
    assertThat(connects.get()).isZero();
    verify(socket).close(eq(1008), anyString());
  }

  @Test
  void expiryBeforeConnectPreservesUnavailableForAlreadyReceivedRequests() throws Exception {
    fixture.flow.http.advance(4000);
    connect();
    assertThat(connects.get()).isZero();
    assertThat(request()).isEqualTo(503);
    assertThat(probe.calls).isZero();
    verify(socket).close(eq(1013), anyString());
  }

  @Test
  void stoppedManagerRejectsNewConnectAsUnavailable() throws Exception {
    sessions.stop();
    connect();
    assertThat(connects.get()).isZero();
    assertThat(request()).isEqualTo(503);
    verify(socket).close(eq(1013), anyString());
  }

  @Test
  void duplicateConnectTerminatesExistingLeaseRatherThanKeepingItUsable() throws Exception {
    connect();
    connect();
    assertThat(connects.get()).isEqualTo(1);
    assertThat(request()).isEqualTo(503);
    verify(socket).close(eq(1013), anyString());
  }

  @Test
  void rejectedRenewalWorkerClosesRatherThanRunningOnDeadlineThread() {
    sessions.stop();
    sessions = new AdmissionWebSocketSessionManager(scheduler, _ -> { throw new RejectedExecutionException(); });
    connect();
    advance(2000);
    verify(socket).close(eq(1013), anyString());
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void rejectedSchedulerClosesAndForcesDisconnectImmediately() {
    doThrow(new RejectedExecutionException()).when(scheduler).schedule(any(Runnable.class), anyLong(), any(TimeUnit.class));
    connect();
    verify(socket).close(eq(1013), anyString());
    verify(socket).disconnect();
    assertThat(connects.get()).isZero();
  }

  @Test
  void shutdownCancelsRenewalAndDoesNotWaitForWorker() {
    connect();
    advance(2000);
    sessions.stop();
    runRenewal();
    verify(socket).disconnect();
    assertThat(fixture.requests.get()).isEqualTo(1);
    assertThrows(AuthenticationUnavailableException.class, () -> sessions.requireCurrent(context));
  }

  @Test
  void renewedProofCannotChangeItsAccountOrDevice() {
    var proof = initial.admissionAuthorization();
    assertThrows(AdmissionEntitlementGate.DeniedException.class,
        () -> proof.renew(UUID.randomUUID(), (byte) 1));
    assertThrows(AdmissionEntitlementGate.DeniedException.class,
        () -> proof.renew(fixture.aci, (byte) 2));
    assertThat(fixture.requests.get()).isEqualTo(1);
  }

  @Test
  void requestWaitOnSqlPoolConsumesOriginalLeaseEvenIfRenewalCouldSucceed() throws Exception {
    var ds = mock(DataSource.class);
    var delay = new java.util.concurrent.atomic.AtomicBoolean();
    when(ds.getConnection()).thenAnswer(call -> {
      if (delay.get()) fixture.flow.http.advance(4000);
      return fixture.flow.ds.getConnection();
    });
    initial = principal(new AdmissionEntitlementGate(ds, fixture.client));
    context.setAuthenticated(initial);
    connect();
    delay.set(true);
    assertThat(request()).isEqualTo(503);
    assertThat(probe.calls).isZero();
    verify(socket).close(eq(1013), anyString());
  }

  @Test
  void managedAsyncWaitAfterFilterMustNotInvokeHandlerWithExpiredOriginalProof() throws Exception {
    connect();
    var response = requestFuture("/probe/async");
    assertThat(managed.queued).hasSize(1);
    assertThat(probe.calls).isZero();
    advance(2000);
    runRenewal();
    advance(2000);
    runRenewal(); // Connection is legitimately renewed; this old request's proof is still expired.
    assertThat(context.getAuthenticated(AuthenticatedDevice.class).admissionAuthorization().remainingNanos()).isPositive();
    managed.queued.remove().run();
    assertThat(response.get(5, TimeUnit.SECONDS).getStatus()).isEqualTo(503);
    assertThat(probe.calls).isZero();
    assertThat(request()).isEqualTo(200);
    verify(socket, never()).close(anyInt(), anyString());
  }

  @Test
  void freshManagedAsyncHandlerRunsThroughDispatchHook() throws Exception {
    connect();
    var response = requestFuture("/probe/async");
    assertThat(managed.queued).hasSize(1);
    managed.queued.remove().run();
    assertThat(response.get(5, TimeUnit.SECONDS).getStatus()).isEqualTo(200);
    assertThat(probe.calls).isEqualTo(1);
  }

  @Test
  void independentDeadlineClosesWhileIssuerCallIsStillBlocked() throws Exception {
    connect();
    CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1);
    fixture.duringHttp = () -> {
      started.countDown();
      boolean done = false;
      while (!done) {
        try { done = release.await(5, TimeUnit.SECONDS); }
        catch (InterruptedException ignored) { /* Deliberately model an uncancellable provider. */ }
      }
    };
    advance(2000);
    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      Future<?> worker = executor.submit(this::runRenewal);
      try {
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
        advance(2000);
        verify(socket).close(eq(1013), anyString());
        assertThat(worker.isDone()).isFalse();
        assertThat(request()).isEqualTo(503);
      } finally { release.countDown(); }
      worker.get(5, TimeUnit.SECONDS);
    }
    assertThat(context.getAuthenticated()).isSameAs(initial);
    assertThat(probe.calls).isZero();
  }
}
