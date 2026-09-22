// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import javax.sql.DataSource;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.chat.device.*;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.controllers.AccountController;
import org.whispersystems.textsecuregcm.controllers.DeviceController;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Native PostgreSQL 18 plus actual HTTP/gRPC dispatch; no SMS or push provider is invoked. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionAccountUpdatesPostgresTest {
  enum Route { ATTRIBUTES, APN, DELETE_APN, GCM, DELETE_GCM, LOCK, DELETE_LOCK, NAME, CAPABILITIES,
    GRPC_NAME, GRPC_APN, GRPC_CLEAR, GRPC_CAPABILITIES }
  enum Changed { SUSPENDED, UNCONFIRMED, ACCOUNT_VERSION, PASSWORD, IDENTITY, SECOND_DEVICE }
  enum Protected { ACI, PNI, IDENTITY, PASSWORD, DEVICE_ID, DEVICE_CREATED, REGISTRATION, PNI_REGISTRATION,
    PROFILE_VERSION, RECOVERY, ACCOUNT_VERSION, SECOND_DEVICE }
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  AccountsManager cache;
  AccountsPostgres store;
  AdmittedAccountUpdates updates;
  Executor worker = Runnable::run;
  Runnable afterConnection = () -> {}, afterWrite = () -> {}, afterCommit = () -> {}, afterClose = () -> {}, duringEviction = () -> {};
  AtomicInteger writes = new AtomicInteger(), evictions = new AtomicInteger();
  DataSource writeDataSource;
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  DevicesGrpc.DevicesBlockingStub grpc;
  boolean retainOriginal;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    writeDataSource = mock(DataSource.class);
    when(writeDataSource.getConnection()).thenAnswer(_ -> {
      var actual = fixture.flow.ds.getConnection(); afterConnection.run();
      return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class}, (_, method, args) -> {
        try {
          Object result = method.invoke(actual, args);
          if (method.getName().equals("commit")) afterCommit.run();
          if (method.getName().equals("close")) afterClose.run();
          if (method.getName().equals("prepareStatement") && args[0] instanceof String sql && sql.startsWith("UPDATE signal.accounts")) {
            return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{PreparedStatement.class}, (_, operation, params) -> {
              try {
                Object value = operation.invoke(result, params);
                if (operation.getName().equals("executeUpdate")) { writes.incrementAndGet(); afterWrite.run(); }
                return value;
              } catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
          }
          return result;
        } catch (InvocationTargetException failure) { throw failure.getCause(); }
      });
    });
    store = new AccountsPostgres(writeDataSource, fixture.flow.http.clock, Runnable::run);
    cache = mock(AccountsManager.class);
    doAnswer(_ -> { evictions.incrementAndGet(); duringEviction.run(); return null; })
        .when(cache).invalidateCacheAfterAdmittedUpdate(any());
    updates = new AdmittedAccountUpdates(store, cache::invalidateCacheAfterAdmittedUpdate, fixture.gate, task -> worker.execute(task));
    var controller = new AccountController(cache, mock(RateLimiters.class), mock(PhoneNumberRecoveryPasswordsManager.class),
        null, EnumSet.allOf(PushNotification.TokenType.class), AccountOperationsPolicy.PILOT_PRIMARY_ONLY, updates);
    var devices = new DeviceController(cache, mock(RateLimiters.class), null,
        EnumSet.allOf(PushNotification.TokenType.class), AccountOperationsPolicy.PILOT_PRIMARY_ONLY, updates);
    var live = AccountAuthenticator.withAdmission(fixture.gate); var auth = mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call -> retainOriginal ? Optional.of(principal) : live.authenticate(call.getArgument(0)));
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(io.dropwizard.jersey.validation.FuzzyEnumParamConverterProvider.class)
        .register(org.whispersystems.textsecuregcm.mappers.FeatureUnavailableExceptionMapper.class)
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>().setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class)).register(controller).register(devices));
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(new DevicesGrpcService(cache,
            EnumSet.allOf(PushNotification.TokenType.class), AccountOperationsPolicy.PILOT_PRIMARY_ONLY, updates),
            new MockRequestAttributesInterceptor(), new RequireAuthenticationInterceptor(auth))).build().start();
    channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata = new io.grpc.Metadata(); metadata.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    grpc = DevicesGrpc.newBlockingStub(channel).withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
  }
  @AfterEach void close() throws Exception {
    if (channel != null) channel.shutdownNow(); if (server != null) server.shutdownNow();
    if (jersey != null) jersey.onShutdown(null); if (fixture != null) fixture.close();
  }
  Account account() { return new AccountsPostgres(fixture.flow.ds, fixture.flow.http.clock, Runnable::run).getByAccountIdentifier(fixture.aci).orElseThrow(); }
  String row() throws Exception { try (var c = fixture.flow.ds.getConnection(); var s = c.createStatement(); var r = s.executeQuery("SELECT to_jsonb(a)::text FROM signal.accounts a")) { r.next(); return r.getString(1); } }
  void expire() { fixture.flow.http.advance(4000); }
  AdmissionAccountMutationGuard guard() { return AdmissionAccountMutationGuard.http(fixture.gate, principal); }
  static void changeName(Account a) { a.getPrimaryDevice().setName(new byte[]{1, 2, 3}); }
  ContainerResponse http(String method, String path, Object body) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"), URI.create("http://localhost" + path), method,
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), jersey.getConfiguration());
    request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    if (body != null) { request.header("Content-Type", "application/json"); request.setEntityStream(new java.io.ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(body))); }
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }
  Object invoke(Route route) throws Exception {
    return switch (route) {
      case ATTRIBUTES -> http("PUT", "/v1/accounts/attributes/", Map.of("unidentifiedAccessKey", Base64.getEncoder().encodeToString(new byte[16]), "registrationId", 123, "fetchesMessages", true, "name", "AQID", "capabilities", Map.of("spqr", true), "discoverableByPhoneNumber", false));
      case APN -> http("PUT", "/v1/accounts/apn/", Map.of("apnRegistrationId", "synthetic-token"));
      case DELETE_APN -> http("DELETE", "/v1/accounts/apn/", null);
      case GCM -> http("PUT", "/v1/accounts/gcm/", Map.of("gcmRegistrationId", "synthetic-token"));
      case DELETE_GCM -> http("DELETE", "/v1/accounts/gcm/", null);
      case LOCK -> http("PUT", "/v1/accounts/registration_lock", Map.of("registrationLock", "1".repeat(64)));
      case DELETE_LOCK -> http("DELETE", "/v1/accounts/registration_lock", null);
      case NAME -> http("PUT", "/v1/accounts/name/", Map.of("deviceName", "AQID"));
      case CAPABILITIES -> http("PUT", "/v1/devices/capabilities", Map.of("spqr", true));
      case GRPC_NAME -> grpc.setDeviceName(SetDeviceNameRequest.newBuilder().setId(1).setName(ByteString.copyFrom(new byte[]{1,2,3})).build());
      case GRPC_APN -> grpc.setPushToken(SetPushTokenRequest.newBuilder().setApnsTokenRequest(SetPushTokenRequest.ApnsTokenRequest.newBuilder().setApnsToken("synthetic-token")).build());
      case GRPC_CLEAR -> grpc.clearPushToken(ClearPushTokenRequest.getDefaultInstance());
      case GRPC_CAPABILITIES -> grpc.setCapabilities(SetCapabilitiesRequest.newBuilder().addCapabilities(org.signal.chat.common.DeviceCapability.DEVICE_CAPABILITY_SPARSE_POST_QUANTUM_RATCHET).build());
    };
  }
  void failure(Route route, int status) throws Exception {
    if (route.name().startsWith("GRPC")) {
      assertThat(assertThrows(StatusRuntimeException.class, () -> invoke(route)).getStatus().getCode())
          .isEqualTo(status == 401 ? Status.Code.UNAUTHENTICATED : Status.Code.UNAVAILABLE);
    } else assertThat(((ContainerResponse) invoke(route)).getStatus()).isEqualTo(status);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void actualRoutesCommitExactlyOneNativeUpdateAndEvict(Route route) throws Exception {
    int version = account().getVersion();
    Object response = invoke(route);
    if (response instanceof ContainerResponse http) assertThat(http.getStatus()).isEqualTo(204);
    assertThat(account().getVersion()).isEqualTo(version + 1);
    assertThat(writes.get()).isEqualTo(1); assertThat(evictions.get()).isEqualTo(1);
    switch (route) {
      case ATTRIBUTES, NAME, GRPC_NAME -> assertThat(account().getPrimaryDevice().getName()).containsExactly(1, 2, 3);
      case APN, GRPC_APN -> assertThat(account().getPrimaryDevice().getApnId()).isEqualTo("synthetic-token");
      case GCM -> assertThat(account().getPrimaryDevice().getGcmId()).isEqualTo("synthetic-token");
      case LOCK -> assertThat(account().getRegistrationLock().isPresent()).isTrue();
      default -> {}
    }
    verify(cache, never()).getByAccountIdentifier(any());
    verify(cache, never()).update(any(UUID.class), any(Consumer.class));
    assertThrows(RuntimeException.class, () -> principal.admissionAuthorization().requireCurrent(fixture.aci, (byte) 1));
  }
  @ParameterizedTest @EnumSource(Route.class)
  void originalProofCannotSurviveExecutorWait(Route route) throws Exception {
    String original = row(); worker = task -> { expire(); task.run(); };
    failure(route, 503); assertThat(row()).isEqualTo(original); assertThat(writes.get()).isZero();
  }
  @ParameterizedTest @EnumSource(Route.class)
  void secondaryDeviceFailsBeforeNativeWrite(Route route) throws Exception {
    retainOriginal = true; principal = new AuthenticatedDevice(fixture.aci, (byte) 2, principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    if (route == Route.GRPC_NAME) {
      assertThat(assertThrows(StatusRuntimeException.class, () -> invoke(route)).getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
    } else failure(route, route == Route.NAME ? 503 : 401);
    verifyNoInteractions(writeDataSource, cache);
  }
  @Test void missingDeviceProofCannotWrite() throws Exception {
    retainOriginal = true; principal = new AuthenticatedDevice(fixture.aci, (byte) 1, principal.primaryDeviceLastSeen());
    failure(Route.ATTRIBUTES, 401); verifyNoInteractions(writeDataSource, cache);
  }
  @ParameterizedTest @EnumSource(Changed.class)
  void interveningChangesAreNeverAdopted(Changed changed) throws Exception {
    var guard = guard();
    switch (changed) {
      case SUSPENDED -> fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp()");
      case UNCONFIRMED -> fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL");
      case ACCOUNT_VERSION -> fixture.sql("UPDATE signal.accounts SET version=version+1");
      case PASSWORD -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"rotated\"')");
      case IDENTITY -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{identityKey}','\"changed\"')");
      case SECOND_DEVICE -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices}',(data->'devices') || jsonb_build_object('id',2))");
    }
    String original = row();
    assertThrows(AdmissionAccountMutationGuard.Failure.class, () -> updates.update(guard, AdmissionAccountUpdatesPostgresTest::changeName));
    assertThat(row()).isEqualTo(original); assertThat(writes.get()).isZero();
  }
  @ParameterizedTest @EnumSource(Protected.class)
  void protectedFieldsCannotBeChangedByMutationCallback(Protected field) throws Exception {
    String original = row(); var guard = guard();
    assertThrows(AdmissionAccountMutationGuard.Failure.class, () -> updates.update(guard, a -> {
      switch (field) {
        case ACI -> a.setAccountIdentifier(UUID.randomUUID());
        case PNI -> a.setNumber(a.getNumber().orElseThrow(), UUID.randomUUID());
        case IDENTITY -> a.setIdentityKey(new org.signal.libsignal.protocol.IdentityKey(org.signal.libsignal.protocol.ecc.ECKeyPair.generate().getPublicKey()));
        case PASSWORD -> a.getPrimaryDevice().setAuthTokenHash(SaltedTokenHash.generateFor("replacement"));
        case DEVICE_ID -> a.getPrimaryDevice().setId((byte) 2);
        case DEVICE_CREATED -> a.getPrimaryDevice().setCreated(1234);
        case REGISTRATION -> a.getPrimaryDevice().setRegistrationId(1234);
        case PNI_REGISTRATION -> a.getPrimaryDevice().setPhoneNumberIdentityRegistrationId(1234);
        case PROFILE_VERSION -> a.setCurrentProfileVersion(new byte[]{1,2});
        case RECOVERY -> a.setAccountRecoveryPassword(new byte[32]);
        case ACCOUNT_VERSION -> a.setVersion(a.getVersion()+1);
        case SECOND_DEVICE -> { var d = new org.whispersystems.textsecuregcm.storage.Device(); d.setId((byte) 2); a.addDevice(d); }
      }
    }));
    assertThat(row()).isEqualTo(original); assertThat(writes.get()).isZero();
  }
  @Test void expiryAfterActualUpdateRollsBackDataAndVersion() throws Exception {
    String original = row(); afterWrite = this::expire;
    failure(Route.ATTRIBUTES, 503); assertThat(writes.get()).isEqualTo(1); assertThat(row()).isEqualTo(original); assertThat(evictions.get()).isEqualTo(1);
  }
  @Test void poolAcquisitionConsumesOriginalDeadline() throws Exception {
    String original = row(); afterConnection = this::expire;
    failure(Route.GRPC_NAME, 503); assertThat(writes.get()).isZero(); assertThat(row()).isEqualTo(original);
  }
  @Test void closeExpirySuppressesResponseButCommittedWriteStillEvicts() throws Exception {
    int version = account().getVersion(); afterClose = this::expire;
    failure(Route.ATTRIBUTES, 503); assertThat(account().getVersion()).isEqualTo(version+1); assertThat(evictions.get()).isEqualTo(1);
  }
  @Test void commitExpirySuppressesResponseButCommittedWriteStillEvicts() throws Exception {
    int version = account().getVersion(); afterCommit = this::expire;
    failure(Route.GRPC_NAME, 503); assertThat(account().getVersion()).isEqualTo(version+1); assertThat(evictions.get()).isEqualTo(1);
  }
  @Test void cacheWaitCannotExtendResultDeadline() throws Exception {
    int version = account().getVersion(); duringEviction = this::expire;
    failure(Route.ATTRIBUTES, 503); assertThat(account().getVersion()).isEqualTo(version+1);
  }
  @Test void cacheFailureFailsClosedAfterCommit() throws Exception {
    int version = account().getVersion(); duringEviction = () -> { throw new IllegalStateException("synthetic cache outage"); };
    failure(Route.GRPC_NAME, 503); assertThat(account().getVersion()).isEqualTo(version+1);
  }
  @Test void concurrentPostcommitMutationIsNotAdoptedByResultProof() throws Exception {
    duringEviction = () -> fixture.sql("UPDATE signal.accounts SET version=version+1");
    failure(Route.ATTRIBUTES, 503); assertThat(writes.get()).isEqualTo(1);
  }
  @Test void postcommitSuspensionRejectsResult() throws Exception {
    duringEviction = () -> fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp()");
    failure(Route.GRPC_NAME, 401); assertThat(writes.get()).isEqualTo(1);
  }
  @Test void sameGuardCannotMutateTwice() {
    var guard = guard(); updates.update(guard, AdmissionAccountUpdatesPostgresTest::changeName);
    assertThrows(AdmissionAccountMutationGuard.Failure.class, () -> updates.update(guard, AdmissionAccountUpdatesPostgresTest::changeName));
    assertThat(writes.get()).isEqualTo(1);
  }
  @Test void nextRequestNeedsFreshBasicProofAndCanSucceed() throws Exception {
    invoke(Route.ATTRIBUTES); invoke(Route.GRPC_NAME);
    assertThat(writes.get()).isEqualTo(2); assertThat(evictions.get()).isEqualTo(2);
  }
  @Test void executorRejectionDoesNotWrite() throws Exception {
    worker = _ -> { throw new RejectedExecutionException("synthetic saturation"); };
    failure(Route.ATTRIBUTES, 503); assertThat(writes.get()).isZero(); verifyNoInteractions(writeDataSource, cache);
  }
  @Test void unavailableDatabaseDoesNotWrite() throws Exception {
    doThrow(new java.sql.SQLException("synthetic")).when(writeDataSource).getConnection();
    failure(Route.GRPC_NAME, 503); assertThat(writes.get()).isZero();
  }
  @Test void callbackFailureRollsBackWithoutWrite() throws Exception {
    String original = row(); var guard = guard();
    assertThrows(AdmissionAccountMutationGuard.Failure.class, () -> updates.update(guard, a -> { changeName(a); throw new IllegalStateException("synthetic"); }));
    assertThat(row()).isEqualTo(original); assertThat(writes.get()).isZero();
  }
  @Test void actualAccountLockWaitCannotOutliveOriginalReceipt() throws Exception {
    String original = row(); var guard = guard();
    try (var executor = Executors.newVirtualThreadPerTaskExecutor(); var blocker = fixture.flow.ds.getConnection()) {
      blocker.setAutoCommit(false);
      try (var s = blocker.createStatement()) { s.execute("SELECT aci FROM signal.accounts FOR UPDATE"); }
      var future = CompletableFuture.runAsync(() -> updates.update(guard, AdmissionAccountUpdatesPostgresTest::changeName), executor);
      try {
        long deadline = System.nanoTime()+TimeUnit.SECONDS.toNanos(5); boolean waiting = false;
        while (System.nanoTime() < deadline && !waiting) {
          waiting = fixture.flow.count("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT * FROM signal.accounts%'") > 0;
          if (!waiting) Thread.sleep(10);
        }
        assertThat(waiting).isTrue(); expire();
      } finally { blocker.rollback(); }
      assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
      assertThat(row()).isEqualTo(original); assertThat(writes.get()).isZero();
    }
  }
}
