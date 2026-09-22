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
import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.ApplicationHandler;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ContainerResponse;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.chat.credentials.*;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.controllers.CertificateController;
import org.whispersystems.textsecuregcm.entities.DeliveryCertificate;
import org.whispersystems.textsecuregcm.entities.GroupCredentials;
import org.whispersystems.textsecuregcm.entities.MessageProtos;
import org.whispersystems.textsecuregcm.grpc.CredentialsGrpcService;
import org.whispersystems.textsecuregcm.grpc.MockRequestAttributesInterceptor;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.UUIDUtil;

/** Native membership state, real libsignal signatures/ZK issuance, actual Jersey and gRPC dispatch. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionCredentialsPostgresTest {
  enum Route { HTTP_DELIVERY, HTTP_GROUP, GRPC_DELIVERY, GRPC_GROUP, GRPC_EXTERNAL }
  enum Change { EXPIRE, SUSPEND, ROTATE_DEVICE, UNCONFIRM }
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  AccountsManager accounts;
  CertificateGenerator signer;
  ECKeyPair signingKey;
  ServerSecretParams zkSecret;
  ServerZkAuthOperations zk;
  ExternalServiceCredentialsGenerator external;
  RateLimiters rates;
  RateLimiter limiter;
  CertificateController controller;
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  CredentialsGrpc.CredentialsBlockingStub grpc;
  boolean retainOriginalAuthentication;
  long redemption;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest();
    fixture.setup();
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    accounts = mock(AccountsManager.class);
    // Any cache fallback fails; the authenticated SQL snapshot owns identity/number/PNI inputs.
    when(accounts.getByAccountIdentifier(any())).thenThrow(new AssertionError("Unexpected account-cache fallback"));
    signingKey = ECKeyPair.generate();
    byte[] certificate = MessageProtos.ServerCertificate.newBuilder()
        .setCertificate(MessageProtos.ServerCertificate.Certificate.newBuilder().setId(1)
            .setKey(ByteString.copyFrom(signingKey.getPublicKey().serialize())).build().toByteString())
        .setSignature(ByteString.copyFrom(new byte[64])).build().toByteArray();
    signer = spy(new CertificateGenerator(certificate, signingKey.getPrivateKey(), 1, false));
    zkSecret = ServerSecretParams.generate();
    zk = spy(new ServerZkAuthOperations(zkSecret));
    external = mock(ExternalServiceCredentialsGenerator.class);
    when(external.generateForUuid(fixture.aci)).thenReturn(new ExternalServiceCredentials("synthetic", "fixture-only"));
    rates = mock(RateLimiters.class); limiter = mock(RateLimiter.class);
    when(rates.forDescriptor(RateLimiters.For.EXTERNAL_SERVICE_CREDENTIALS)).thenReturn(limiter);
    redemption = fixture.flow.http.clock.instant().truncatedTo(ChronoUnit.DAYS).getEpochSecond();
    controller = new CertificateController(accounts, signer, zk, null, null, fixture.flow.http.clock, false, true);
    var liveAuthenticator = AccountAuthenticator.withAdmission(fixture.gate);
    var authenticator = mock(AccountAuthenticator.class);
    when(authenticator.authenticate(any())).thenAnswer(call -> retainOriginalAuthentication
        ? Optional.of(principal) : liveAuthenticator.authenticate(call.getArgument(0)));
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
            .setRealm("fixture").setAuthenticator(authenticator).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class)).register(controller));
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(new CredentialsGrpcService(accounts, signer, zk, null,
            rates, fixture.flow.http.clock, Map.of(ExternalServiceType.EXTERNAL_SERVICE_TYPE_DIRECTORY, external),
            false, true), new MockRequestAttributesInterceptor(), new RequireAuthenticationInterceptor(authenticator)))
        .build().start();
    channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata = new io.grpc.Metadata();
    metadata.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    grpc = CredentialsGrpc.newBlockingStub(channel)
        .withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
    clearInvocations(accounts, signer, zk, external, rates, limiter);
  }

  @AfterEach void cleanup() throws Exception {
    if (channel != null) channel.shutdownNow();
    if (server != null) server.shutdownNow();
    if (jersey != null) jersey.onShutdown(null);
    if (fixture != null) fixture.close();
  }

  ContainerResponse http(String path) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"), URI.create("http://localhost" + path), "GET",
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), null);
    request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }
  String groupPath() { return "/v1/certificate/auth/group?redemptionStartSeconds=" + redemption
      + "&redemptionEndSeconds=" + (redemption + 86400); }
  GetGroupCredentialsRequest groupRequest() { return GetGroupCredentialsRequest.newBuilder()
      .setRedemptionStartSeconds(redemption).setRedemptionEndSeconds(redemption + 86400).build(); }
  Object invoke(Route route) throws Exception {
    return switch (route) {
      case HTTP_DELIVERY -> http("/v1/certificate/delivery");
      case HTTP_GROUP -> http(groupPath());
      case GRPC_DELIVERY -> grpc.getDeliveryCertificate(GetDeliveryCertificateRequest.getDefaultInstance());
      case GRPC_GROUP -> grpc.getGroupCredentials(groupRequest());
      case GRPC_EXTERNAL -> grpc.getExternalServiceCredentials(GetExternalServiceCredentialsRequest.newBuilder()
          .setExternalService(ExternalServiceType.EXTERNAL_SERVICE_TYPE_DIRECTORY).build());
    };
  }
  void assertFailure(Route route, boolean unavailable) throws Exception {
    if (route.name().startsWith("HTTP")) {
      ContainerResponse response = (ContainerResponse) invoke(route);
      assertThat(response.getStatus()).isEqualTo(unavailable ? 503 : 401);
      assertThat(response.getEntity()).isNull();
    } else {
      var failure = assertThrows(StatusRuntimeException.class, () -> invoke(route));
      assertThat(failure.getStatus().getCode()).isEqualTo(unavailable ? Status.Code.UNAVAILABLE : Status.Code.UNAUTHENTICATED);
    }
  }
  void change(Change change) {
    switch (change) {
      case EXPIRE -> fixture.flow.http.advance(4000);
      case SUSPEND -> fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()");
      case ROTATE_DEVICE -> fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"!changed\"')");
      case UNCONFIRM -> fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL");
    }
  }
  boolean unavailable(Change change) { return change == Change.EXPIRE || change == Change.ROTATE_DEVICE; }
  void changeDuringSigning(Route route, Change change) {
    switch (route) {
      case HTTP_DELIVERY, GRPC_DELIVERY -> doAnswer(call -> {
        var result = call.callRealMethod(); change(change); return result;
      }).when(signer).createFor(any(), anyByte(), anyBoolean());
      case HTTP_GROUP, GRPC_GROUP -> doAnswer(call -> {
        var result = call.callRealMethod(); change(change); return result;
      }).when(zk).issueAuthCredentialWithPniZkc(any(), any(), any());
      case GRPC_EXTERNAL -> when(external.generateForUuid(fixture.aci)).thenAnswer(_ -> {
        change(change); return new ExternalServiceCredentials("synthetic", "fixture-only");
      });
    }
  }
  void validateCertificate(byte[] bytes, boolean withNumber) throws Exception {
    var holder = MessageProtos.SenderCertificate.parseFrom(bytes);
    assertThat(signingKey.getPublicKey().verifySignature(holder.getCertificate().toByteArray(), holder.getSignature().toByteArray())).isTrue();
    var certificate = MessageProtos.SenderCertificate.Certificate.parseFrom(holder.getCertificate());
    assertThat(certificate.getSenderUuid()).isEqualTo(UUIDUtil.toByteString(fixture.aci));
    assertThat(certificate.getSenderDevice()).isEqualTo(1);
    assertThat(certificate.getIdentityKey().toByteArray()).isEqualTo(fixture.flow.keys.aci.serialize());
    assertThat(certificate.hasSenderE164()).isEqualTo(withNumber);
    if (withNumber) assertThat(certificate.getSenderE164()).isEqualTo(fixture.flow.input.requestedNumber());
  }
  void validateGroup(byte[] bytes, long time) throws Exception {
    new ClientZkAuthOperations(zkSecret.getPublicParams()).receiveAuthCredentialWithPniAsServiceId(
        new ServiceId.Aci(fixture.aci), new ServiceId.Pni(principal.admissionAuthorization().accountProjection().pni()),
        time, new AuthCredentialWithPniResponse(bytes));
  }

  @Test void actualHttpAndGrpcDeliverySignAuthenticatedSqlIdentity() throws Exception {
    var http = http("/v1/certificate/delivery");
    assertThat(http.getStatus()).isEqualTo(200);
    validateCertificate(((DeliveryCertificate) http.getEntity()).getCertificate(), true);
    var response = grpc.getDeliveryCertificate(GetDeliveryCertificateRequest.getDefaultInstance());
    validateCertificate(response.getCertificateWithE164().toByteArray(), true);
    validateCertificate(response.getCertificateWithoutE164().toByteArray(), false);
    verifyNoInteractions(accounts);
  }
  @Test void actualHttpAndGrpcGroupCredentialsAreValidWithoutCallCapabilities() throws Exception {
    var http = http(groupPath());
    assertThat(http.getStatus()).isEqualTo(200);
    var response = (GroupCredentials) http.getEntity();
    assertThat(response.credentials()).hasSize(2);
    assertThat(response.callLinkAuthCredentials()).isEmpty();
    for (var credential : response.credentials()) validateGroup(credential.credential(), credential.redemptionTime());
    var grpcResponse = grpc.getGroupCredentials(groupRequest());
    assertThat(grpcResponse.getGroupCredentialsCount()).isEqualTo(2);
    assertThat(grpcResponse.getCallLinkAuthCredentialsCount()).isZero();
    for (var credential : grpcResponse.getGroupCredentialsList()) validateGroup(credential.getCredential().toByteArray(), credential.getRedemptionTime());
    verifyNoInteractions(accounts);
  }
  @Test void detachedIssuanceCopyCannotMutateProofOrSql() {
    var copy = principal.admissionAuthorization().accountForCredentialIssuance(fixture.aci, (byte) 1);
    copy.setNumber("+13055550999", UUID.randomUUID());
    copy.getPrimaryDevice().setCreated(0);
    var next = principal.admissionAuthorization().accountForCredentialIssuance(fixture.aci, (byte) 1);
    assertThat(next.getNumber()).contains(fixture.flow.input.requestedNumber());
    assertThat(next.getPrimaryDevice().getCreated()).isNotZero();
  }
  @ParameterizedTest @EnumSource(Route.class)
  void prooflessPrincipalsCannotIssue(Route route) throws Exception {
    retainOriginalAuthentication = true;
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, principal.primaryDeviceLastSeen());
    assertFailure(route, false); verifyNoInteractions(signer, zk, external, limiter, accounts);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void secondaryPrincipalsCannotIssue(Route route) throws Exception {
    retainOriginalAuthentication = true;
    principal = new AuthenticatedDevice(fixture.aci, (byte) 2, principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    assertFailure(route, false); verifyNoInteractions(signer, zk, external, limiter, accounts);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void proofCannotBeReboundToAnotherAccount(Route route) throws Exception {
    retainOriginalAuthentication = true;
    principal = new AuthenticatedDevice(UUID.randomUUID(), (byte) 1, principal.primaryDeviceLastSeen(), principal.admissionAuthorization());
    assertFailure(route, false); verifyNoInteractions(signer, zk, external, limiter, accounts);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void expiredRetainedProofCannotBorrowFreshEntitlement(Route route) throws Exception {
    retainOriginalAuthentication = true;
    change(Change.EXPIRE);
    assertFailure(route, true);
    assertThat(fixture.requests.get()).isEqualTo(1);
    verifyNoInteractions(signer, zk, external, limiter, accounts);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void expiryDuringSigningSuppressesEntireResult(Route route) throws Exception {
    changeDuringSigning(route, Change.EXPIRE); assertFailure(route, true);
    if (route == Route.GRPC_DELIVERY) verify(signer, times(1)).createFor(any(), anyByte(), anyBoolean());
    if (route == Route.HTTP_GROUP || route == Route.GRPC_GROUP)
      verify(zk, times(1)).issueAuthCredentialWithPniZkc(any(), any(), any());
  }
  @ParameterizedTest @EnumSource(Route.class)
  void suspensionDuringSigningSuppressesEntireResult(Route route) throws Exception {
    changeDuringSigning(route, Change.SUSPEND); assertFailure(route, false);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void deviceRotationDuringSigningSuppressesEntireResult(Route route) throws Exception {
    changeDuringSigning(route, Change.ROTATE_DEVICE); assertFailure(route, true);
  }
  @ParameterizedTest @EnumSource(Route.class)
  void lostConfirmationDuringSigningSuppressesEntireResult(Route route) throws Exception {
    changeDuringSigning(route, Change.UNCONFIRM); assertFailure(route, false);
  }
  @ParameterizedTest @EnumSource(Change.class)
  void externalRateLimitWaitCannotAuthorizeSigning(Change change) throws Exception {
    doAnswer(_ -> { change(change); return null; }).when(limiter).validate(fixture.aci);
    assertFailure(Route.GRPC_EXTERNAL, unavailable(change)); verifyNoInteractions(external);
  }
  @Test void externalCredentialsWithCurrentProofAreReturned() {
    var response = grpc.getExternalServiceCredentials(GetExternalServiceCredentialsRequest.newBuilder()
        .setExternalService(ExternalServiceType.EXTERNAL_SERVICE_TYPE_DIRECTORY).build());
    assertThat(response.getUsername()).isEqualTo("synthetic");
    verify(external).generateForUuid(fixture.aci);
  }
  @Test void callsStayUnavailableBeforeDependencies() {
    assertThat(assertThrows(StatusRuntimeException.class,
        () -> grpc.getCreateCallLinkCredential(GetCreateCallLinkCredentialRequest.getDefaultInstance()))
        .getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(signer, zk, external, accounts, rates);
  }
}
