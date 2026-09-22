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
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.chat.keys.*;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.controllers.KeysController;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.identity.*;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import reactor.adapter.JdkFlowAdapter;
import reactor.core.publisher.Flux;

/** Real native key transactions and real Jersey/gRPC dispatch; private membership is synthetic. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionKeysPostgresTest {
  enum Route { HTTP_SET, HTTP_COUNT, HTTP_CHECK, HTTP_FETCH, GRPC_EC, GRPC_KEM, GRPC_SIGNED, GRPC_LAST, GRPC_COUNT, GRPC_FETCH }
  enum Operation { PUBLISH, TAKE, COUNT, REPEATED }
  enum Change { EXPIRE, SUSPEND, ROTATE, UNCONFIRM }
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  AccountsManager accounts;
  RateLimiters rates;
  RateLimiter limiter;
  AdmittedKeysPostgres nativeKeys;
  KeysController controller;
  KeysManager legacyKeys;
  Executor worker = Runnable::run;
  Runnable afterConnection = () -> {}, afterKeySql = () -> {}, afterClose = () -> {};
  DataSource keyDataSource;
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  KeysGrpc.KeysBlockingStub grpc;
  UUID pni;
  boolean retainOriginal;
  ECPreKey ec;
  ECSignedPreKey signed;
  KEMSignedPreKey kem;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    try (var c = fixture.flow.ds.getConnection(); var s = c.createStatement()) {
      for (String migration : List.of("002-ec-prekeys", "005-kem-prekeys"))
        s.execute(Files.readString(Path.of("../bconnected/migrations/" + migration + ".sql")));
      s.execute("TRUNCATE signal.single_use_ec_prekeys,signal.single_use_kem_prekeys");
    }
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    pni = proof.accountProjection().pni();
    ec = new ECPreKey(101, ECKeyPair.generate().getPublicKey());
    signed = fixture.flow.keys.activation.aciSignedPreKey();
    kem = fixture.flow.keys.activation.aciPqLastResortPreKey();
    seed(fixture.aci, kem); seed(pni, fixture.flow.keys.activation.pniPqLastResortPreKey().orElseThrow());
    accounts = mock(AccountsManager.class); legacyKeys = mock(KeysManager.class);
    when(accounts.getByServiceIdentifier(any())).thenAnswer(call -> {
      ServiceIdentifier id = call.getArgument(0);
      return new AccountsPostgres(fixture.flow.ds, fixture.flow.http.clock, Runnable::run).getByAccountIdentifier(fixture.aci)
          .filter(account -> account.isIdentifiedBy(id));
    });
    rates = mock(RateLimiters.class); limiter = mock(RateLimiter.class);
    when(rates.getPreKeysLimiter()).thenReturn(limiter);
    keyDataSource = mock(DataSource.class);
    when(keyDataSource.getConnection()).thenAnswer(_ -> {
      var actual = fixture.flow.ds.getConnection(); afterConnection.run();
      return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Connection.class}, (_, method, args) -> {
        try {
          Object result = method.invoke(actual, args);
          if (method.getName().equals("close")) afterClose.run();
          if (method.getName().equals("prepareStatement") && args[0] instanceof String sql && sql.contains("prekeys")) {
            return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{PreparedStatement.class}, (_, operation, params) -> {
              try {
                Object value = operation.invoke(result, params);
                if (operation.getName().startsWith("execute")) afterKeySql.run();
                return value;
              } catch (InvocationTargetException failure) { throw failure.getCause(); }
            });
          }
          return result;
        } catch (InvocationTargetException failure) { throw failure.getCause(); }
      });
    });
    nativeKeys = new AdmittedKeysPostgres(keyDataSource, task -> worker.execute(task));
    controller = new KeysController(rates, legacyKeys, accounts, ServerSecretParams.generate(), fixture.flow.http.clock,
        fixture.gate, nativeKeys);
    var live = AccountAuthenticator.withAdmission(fixture.gate); var auth = mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call -> retainOriginal ? Optional.of(principal) : live.authenticate(call.getArgument(0)));
    jersey = new ApplicationHandler(new ResourceConfig()
        .property(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE, true)
        .register(io.dropwizard.jersey.validation.FuzzyEnumParamConverterProvider.class)
        .register(org.whispersystems.textsecuregcm.mappers.CompletionExceptionMapper.class)
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>().setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class)).register(controller));
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(new KeysGrpcService(accounts, legacyKeys, rates, fixture.gate, nativeKeys),
            new MockRequestAttributesInterceptor(), new RequireAuthenticationInterceptor(auth))).build().start();
    channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata = new io.grpc.Metadata(); metadata.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    grpc = KeysGrpc.newBlockingStub(channel).withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
    clearInvocations(legacyKeys, accounts, rates, limiter);
  }
  void seed(UUID id, KEMSignedPreKey key) {
    new SingleUseECPreKeysPostgres(fixture.flow.ds, Runnable::run).store(id, (byte) 1, List.of(ec)).join();
    new SingleUseKEMPreKeysPostgres(fixture.flow.ds, Runnable::run).store(id, (byte) 1, List.of(key)).join();
  }
  @AfterEach void close() throws Exception {
    if (channel != null) channel.shutdownNow(); if (server != null) server.shutdownNow();
    if (jersey != null) jersey.onShutdown(null); if (fixture != null) fixture.close();
  }
  AdmissionKeyGuard guard() { return AdmissionKeyGuard.http(fixture.gate, principal); }
  SetKeysRequest publication() { return new SetKeysRequest(List.of(ec), signed, List.of(kem), kem); }
  org.signal.chat.common.EcSignedPreKey signedWire() { return org.signal.chat.common.EcSignedPreKey.newBuilder()
      .setKeyId((int) signed.keyId()).setPublicKey(ByteString.copyFrom(signed.serializedPublicKey()))
      .setSignature(ByteString.copyFrom(signed.signature())).build(); }
  org.signal.chat.common.KemSignedPreKey kemWire() { return org.signal.chat.common.KemSignedPreKey.newBuilder()
      .setKeyId((int) kem.keyId()).setPublicKey(ByteString.copyFrom(kem.serializedPublicKey()))
      .setSignature(ByteString.copyFrom(kem.signature())).build(); }
  ContainerResponse http(String method, String path, Object body) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"), URI.create("http://localhost" + path), method,
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), jersey.getConfiguration());
    request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    if (body != null) { request.header("Content-Type", "application/json"); request.setEntityStream(new java.io.ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(body))); }
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }
  Object invoke(Route route) throws Exception {
    return switch (route) {
      case HTTP_SET -> http("PUT", "/v2/keys", publication());
      case HTTP_COUNT -> http("GET", "/v2/keys", null);
      case HTTP_CHECK -> http("POST", "/v2/keys/check", new CheckKeysRequest(IdentityType.ACI, new byte[32]));
      case HTTP_FETCH -> http("GET", "/v2/keys/" + fixture.aci + "/1", null);
      case GRPC_EC -> grpc.setOneTimeEcPreKeys(SetOneTimeEcPreKeysRequest.newBuilder()
          .setIdentityType(org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI)
          .addPreKeys(org.signal.chat.common.EcPreKey.newBuilder().setKeyId((int) ec.keyId()).setPublicKey(ByteString.copyFrom(ec.serializedPublicKey()))).build());
      case GRPC_KEM -> grpc.setOneTimeKemSignedPreKeys(SetOneTimeKemSignedPreKeysRequest.newBuilder()
          .setIdentityType(org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI).addPreKeys(kemWire()).build());
      case GRPC_SIGNED -> grpc.setEcSignedPreKey(SetEcSignedPreKeyRequest.newBuilder()
          .setIdentityType(org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI).setSignedPreKey(signedWire()).build());
      case GRPC_LAST -> grpc.setKemLastResortPreKey(SetKemLastResortPreKeyRequest.newBuilder()
          .setIdentityType(org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI).setSignedPreKey(kemWire()).build());
      case GRPC_COUNT -> grpc.getPreKeyCount(GetPreKeyCountRequest.getDefaultInstance());
      case GRPC_FETCH -> grpc.getPreKeys(GetPreKeysRequest.newBuilder()
          .setTargetIdentifier(GrpcServiceIdentifierUtil.toGrpcServiceIdentifier(new AciServiceIdentifier(fixture.aci))).build());
    };
  }
  void failure(Route route, int status) throws Exception {
    if (route.name().startsWith("HTTP")) assertThat(((ContainerResponse) invoke(route)).getStatus()).isEqualTo(status);
    else assertThat(assertThrows(StatusRuntimeException.class, () -> invoke(route)).getStatus().getCode())
        .isEqualTo(status == 401 ? Status.Code.UNAUTHENTICATED : Status.Code.UNAVAILABLE);
  }
  long ecCount() { return rows("SELECT count(*) FROM signal.single_use_ec_prekeys WHERE account_id='" + fixture.aci + "'"); }
  long kemCount() { return rows("SELECT count(*) FROM signal.single_use_kem_prekeys WHERE account_id='" + fixture.aci + "'"); }
  long rows(String sql) {
    try { return fixture.flow.count(sql); } catch (Exception failure) { throw new RuntimeException(failure); }
  }
  void expire() { fixture.flow.http.advance(4000); }
  void change(Change change) {
    switch (change) {
      case EXPIRE -> expire();
      case SUSPEND -> fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
      case ROTATE -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!changed\"')");
      case UNCONFIRM -> fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL");
    }
  }
  CompletableFuture<?> operation(Operation operation, AdmissionKeyGuard guard) {
    return switch (operation) {
      case PUBLISH -> nativeKeys.publish(guard, IdentityType.ACI, List.of(), signed, List.of(), kem);
      case TAKE -> nativeKeys.take(guard, IdentityType.ACI);
      case COUNT -> nativeKeys.count(guard, IdentityType.ACI);
      case REPEATED -> nativeKeys.repeated(guard, IdentityType.ACI);
    };
  }

  @ParameterizedTest @EnumSource(Route.class)
  void actualRestAndGrpcRoutesUseNativeKeys(Route route) throws Exception {
    Object result = invoke(route);
    if (result instanceof ContainerResponse response) assertThat(response.getStatus()).isEqualTo(route == Route.HTTP_CHECK ? 409 : route == Route.HTTP_SET ? 204 : 200);
    if (result instanceof GetPreKeysResponse response) {
      assertThat(response.getPreKeys().getDevicePreKeysCount()).isEqualTo(1);
      assertThat(response.getPreKeys().getIdentityKey().toByteArray()).isEqualTo(fixture.flow.keys.aci.serialize());
    }
    if (route == Route.HTTP_FETCH || route == Route.GRPC_FETCH) { assertThat(ecCount()).isZero(); assertThat(kemCount()).isZero(); }
    verifyNoInteractions(legacyKeys);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void prooflessPrincipalFailsBeforeAnyKeyOperation(Route route) throws Exception {
    retainOriginal = true; principal = new AuthenticatedDevice(fixture.aci, (byte) 1, principal.primaryDeviceLastSeen());
    failure(route, 401); assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
    verifyNoInteractions(legacyKeys, keyDataSource, accounts, limiter);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void connectionPoolWaitCannotRenewOriginalRequest(Route route) throws Exception {
    afterConnection = this::expire;
    failure(route, 503); assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
  }
  @ParameterizedTest @EnumSource(Operation.class)
  void keySqlWaitRollsBackPublicationAndConsumption(Operation operation) {
    var guard = guard(); afterKeySql = this::expire;
    assertThrows(CompletionException.class, () -> operation(operation, guard).join());
    assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
  }
  @ParameterizedTest @EnumSource(Change.class)
  void queuedOperationRetainsOriginalProof(Change change) {
    var guard = guard(); var queued = new ArrayDeque<Runnable>(); worker = queued::add;
    var result = operation(Operation.PUBLISH, guard); change(change); queued.remove().run();
    assertThrows(CompletionException.class, result::join);
    assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
  }
  @Test void commitAndCloseTimeSuppressResponseWithoutClaimingRollback() {
    var guard = guard(); afterClose = this::expire;
    assertThrows(CompletionException.class, () -> nativeKeys.take(guard, IdentityType.ACI).join());
    // Commit has occurred; suppressing a response cannot restore already-committed one-time keys.
    assertThat(ecCount()).isZero(); assertThat(kemCount()).isZero();
  }
  @Test void rejectedExecutorMapsUnavailableWithoutEffects() {
    worker = _ -> { throw new RejectedExecutionException("synthetic"); };
    var failure = assertThrows(CompletionException.class, () -> nativeKeys.take(guard(), IdentityType.ACI).join());
    assertThat(((jakarta.ws.rs.WebApplicationException) AdmissionKeyGuard.failure(failure).http()).getResponse().getStatus()).isEqualTo(503);
    assertThat(ecCount()).isEqualTo(1);
  }
  @Test void bulkPublicationRollsBackEveryKeyClassOnSqlFailure() {
    var invalid = new KEMSignedPreKey(KeyIdUtil.MAX_KEY_ID + 1, kem.publicKey(), kem.signature());
    assertThrows(CompletionException.class, () -> nativeKeys.publish(guard(), IdentityType.ACI, List.of(), signed, List.of(), invalid).join());
    assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
  }
  @Test void missingRepeatedKeyDoesNotConsumeSingleUseKeys() {
    fixture.sql("DELETE FROM signal.signed_prekeys WHERE identifier='" + fixture.aci + "' AND kind='ec'");
    assertThat(nativeKeys.take(guard(), IdentityType.ACI).join()).isEmpty();
    assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
  }
  @Test void pniKeysAreBoundToTheAuthoritativeIdentity() {
    var guard = guard().forTarget(fixture.aci, new PniServiceIdentifier(pni));
    assertThrows(AdmissionKeyGuard.Failure.class, () -> nativeKeys.take(guard, IdentityType.ACI));
    var result = nativeKeys.take(guard, IdentityType.PNI).join().orElseThrow();
    assertThat(result.ecSignedPreKey()).isEqualTo(fixture.flow.keys.activation.pniSignedPreKey().orElseThrow());
    assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
    assertThrows(AdmissionKeyGuard.Failure.class, () -> nativeKeys.publish(guard, IdentityType.PNI, List.of(), null, null, null));
  }
  @Test void rateLimitWaitCannotConsumeKeysAfterExpiry() throws Exception {
    doAnswer(_ -> { expire(); return null; }).when(limiter).validate(anyString());
    failure(Route.HTTP_FETCH, 503); assertThat(ecCount()).isEqualTo(1);
  }
  @Test void oldCallerProofCannotBorrowNewRecipientReceipt() {
    var guard = guard(); fixture.duringHttp = this::expire;
    assertThrows(AdmissionKeyGuard.Failure.class, () -> guard.forTarget(fixture.aci, new AciServiceIdentifier(fixture.aci)));
    assertThat(ecCount()).isEqualTo(1);
  }
  @Test void anonymousFetchAndFingerprintStreamRejectBeforeDependenciesOrInputDemand() {
    var anonymous = new KeysAnonymousGrpcService(accounts, legacyKeys, ServerSecretParams.generate(), fixture.flow.http.clock, false);
    assertThat(assertThrows(StatusRuntimeException.class, () -> anonymous.getPreKeys(GetPreKeysAnonymousRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    var subscribed = new AtomicBoolean();
    var input = JdkFlowAdapter.publisherToFlowPublisher(Flux.<CheckIdentityKeyRequest>never().doOnSubscribe(_ -> subscribed.set(true)));
    var failure = assertThrows(StatusRuntimeException.class,
        () -> JdkFlowAdapter.flowPublisherToFlux(anonymous.checkIdentityKeys(input)).blockFirst());
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(subscribed).isFalse(); verifyNoInteractions(accounts, legacyKeys);
    assertThat(assertThrows(jakarta.ws.rs.WebApplicationException.class,
        () -> controller.getDeviceKeys(Optional.empty(), Optional.empty(), Optional.empty(), new AciServiceIdentifier(fixture.aci), "1", "fixture"))
        .getResponse().getStatus()).isEqualTo(503);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void secondaryPrincipalFailsBeforeKeyAccess(Route route) throws Exception {
    retainOriginal = true;
    principal = new AuthenticatedDevice(fixture.aci, (byte) 2, principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    failure(route, 401); verifyNoInteractions(keyDataSource, legacyKeys, accounts);
  }
  @Test void realEcRowLockWaitRollsBackAlreadyConsumedKemKey() throws Exception {
    var guard = guard();
    try (var executor = Executors.newVirtualThreadPerTaskExecutor(); var blocker = fixture.flow.ds.getConnection()) {
      worker = executor; blocker.setAutoCommit(false);
      try (var lock = blocker.createStatement()) {
        lock.execute("SELECT key_id FROM signal.single_use_ec_prekeys WHERE account_id='" + fixture.aci + "' FOR UPDATE");
      }
      var result = nativeKeys.take(guard, IdentityType.ACI);
      try {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        boolean waiting = false;
        while (System.nanoTime() < deadline && !waiting) {
          waiting = rows("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%DELETE FROM signal.single_use_ec_prekeys%'") > 0;
          if (!waiting) Thread.sleep(10);
        }
        assertThat(waiting).isTrue();
        expire();
      } finally { blocker.rollback(); }
      assertThrows(ExecutionException.class, () -> result.get(5, TimeUnit.SECONDS));
      assertThat(ecCount()).isEqualTo(1); assertThat(kemCount()).isEqualTo(1);
    }
  }
  @Test void changedCachedIdentityAndRegistrationCannotAlterKeyBundle() throws Exception {
    var stale = guard().account();
    stale.setIdentityKey(new org.signal.libsignal.protocol.IdentityKey(ECKeyPair.generate().getPublicKey()));
    stale.getPrimaryDevice().setRegistrationId(9999);
    doReturn(Optional.of(stale)).when(accounts).getByServiceIdentifier(any());
    var response = (GetPreKeysResponse) invoke(Route.GRPC_FETCH);
    assertThat(response.getPreKeys().getIdentityKey().toByteArray()).isEqualTo(fixture.flow.keys.aci.serialize());
    assertThat(response.getPreKeys().getDevicePreKeysOrThrow(1).getRegistrationId())
        .isEqualTo(fixture.flow.keys.attributes.getRegistrationId());
  }
  @Test void distinctRecipientSuspensionCannotConsumeKeysOrInvalidateCaller() {
    UUID other = UUID.randomUUID();
    fixture.sql("INSERT INTO signal.accounts(aci,pni,number,version,data) SELECT '" + other + "','" + UUID.randomUUID()
        + "','+13055550199',version,data FROM signal.accounts WHERE aci='" + fixture.aci + "'");
    String permit = "33".repeat(32), verification = "44".repeat(32);
    fixture.sql("INSERT INTO signal.admissions SELECT (jsonb_populate_record(NULL::signal.admissions, to_jsonb(a) || jsonb_build_object("
        + "'aci','" + other + "','member_id','" + UUID.randomUUID() + "','signal_operation_id','" + UUID.randomUUID()
        + "','permit_id','\\x" + permit + "','server_verification_session_hash','\\x" + verification + "'))).* FROM signal.admissions a WHERE aci='" + fixture.aci + "'");
    fixture.sql("INSERT INTO signal.admission_confirmation_outbox(permit_id,confirmed_at) VALUES(decode('" + permit + "','hex'),clock_timestamp())");
    var source = guard(); var target = source.forTarget(other, new AciServiceIdentifier(other));
    seed(other, kem);
    fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp() WHERE aci='" + other + "'");
    source.requireCurrent();
    var failure = assertThrows(AdmissionKeyGuard.Failure.class, () -> nativeKeys.take(target, IdentityType.ACI).join());
    assertThat(AdmissionKeyGuard.failure(failure).targetDenied()).isTrue();
    assertThat(rows("SELECT count(*) FROM signal.single_use_ec_prekeys WHERE account_id='" + other + "'")).isEqualTo(1);
  }
  @Test void anonymousRestFingerprintBatchFailsClosedBeforeReadingAccounts() {
    var badges = mock(org.whispersystems.textsecuregcm.configuration.BadgesConfiguration.class);
    when(badges.getBadges()).thenReturn(List.of());
    var profile = new org.whispersystems.textsecuregcm.controllers.ProfileController(fixture.flow.http.clock, rates, accounts,
        mock(ProfilesManager.class), null, null, null, badges, null, ServerSecretParams.generate(), null, Runnable::run, false);
    assertThat(assertThrows(jakarta.ws.rs.WebApplicationException.class,
        () -> profile.runBatchIdentityCheck(new BatchIdentityCheckRequest(List.of()))).getResponse().getStatus()).isEqualTo(503);
    verifyNoInteractions(accounts);
  }

}
