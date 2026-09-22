// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import com.google.auth.ServiceAccountSigner;
import com.google.cloud.storage.*;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.ws.rs.WebApplicationException;
import java.net.URI;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.whispersystems.textsecuregcm.attachments.*;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.configuration.GcsMediaDownloadConfiguration;
import org.whispersystems.textsecuregcm.controllers.*;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.media.GcsMediaDownloadService;
import org.whispersystems.textsecuregcm.util.HeaderUtils;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Native membership snapshots; synthetic rate-limit/storage/signing providers and actual REST/gRPC dispatch. */
@EnabledIfEnvironmentVariable(named = "BCONNECTED_TEST_JDBC_URL", matches = ".+")
class AdmissionCapabilityPostgresTest {
  static final String KEY = "profiles/AAAAAAAAAAAAAAAAAAAAAA==";
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  RateLimiters rates;
  RateLimiter count, bytes;
  GcsAttachmentGenerator uploads;
  ExperimentEnrollmentManager experiments;
  AttachmentControllerV4 attachments;
  GcsMediaDownloadService downloads;
  Storage storage;
  Blob blob;
  MediaDownloadController media;
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  org.signal.chat.attachments.AttachmentsGrpc.AttachmentsBlockingStub grpc;

  @BeforeEach void setup() throws Exception {
    fixture = new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    var proof = fixture.gate.authorizeDevice(fixture.aci, (byte) 1, fixture.flow.input.password());
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, proof.primaryDeviceLastSeen(), proof);
    rates = mock(RateLimiters.class); count = mock(RateLimiter.class); bytes = mock(RateLimiter.class);
    when(rates.getAttachmentLimiter()).thenReturn(count); when(rates.getAttachmentBytesLimiter()).thenReturn(bytes);
    when(rates.getProfileLimiter()).thenReturn(count);
    uploads = mock(GcsAttachmentGenerator.class); experiments = mock(ExperimentEnrollmentManager.class);
    when(uploads.generateAttachment(anyString(), anyLong())).thenReturn(descriptor());
    attachments = new AttachmentControllerV4(rates, uploads, null, experiments, 1024, true);
    storage = mock(Storage.class); blob = mock(Blob.class);
    when(blob.getGeneration()).thenReturn(42L); when(blob.getSize()).thenReturn(100L);
    when(storage.get(any(BlobId.class))).thenReturn(blob);
    when(storage.signUrl(any(BlobInfo.class), anyLong(), any(TimeUnit.class), any(Storage.SignUrlOption[].class)))
        .thenAnswer(_ -> signedUrl());
    downloads = new GcsMediaDownloadService(storage, mock(ServiceAccountSigner.class),
        new GcsMediaDownloadConfiguration("private-avatars", "private-attachments", "", "fixture@test-project.iam.gserviceaccount.com", Duration.ofMinutes(5)),
        fixture.flow.http.clock);
    media = new MediaDownloadController(downloads, rates);
    jersey = new ApplicationHandler(new ResourceConfig()
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>()
            .setRealm("fixture").setAuthenticator(AccountAuthenticator.withAdmission(fixture.gate)).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .register(attachments).register(media));
    String name = io.grpc.inprocess.InProcessServerBuilder.generateName();
    server = io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor()
        .addService(io.grpc.ServerInterceptors.intercept(new AttachmentsGrpcService(experiments, rates, uploads,
            null, null, 1024, fixture.flow.http.clock, true), new MockRequestAttributesInterceptor(),
            new org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor(AccountAuthenticator.withAdmission(fixture.gate))))
        .build().start();
    channel = io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata = new io.grpc.Metadata();
    metadata.put(org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    grpc = org.signal.chat.attachments.AttachmentsGrpc.newBlockingStub(channel)
        .withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
    clearInvocations(rates, count, bytes, uploads, storage);
  }

  @AfterEach void cleanup() throws Exception {
    if (channel != null) channel.shutdownNow(); if (server != null) server.shutdownNow();
    if (jersey != null) jersey.onShutdown(null);
    if (downloads != null) downloads.close(); if (fixture != null) fixture.close();
  }
  AttachmentGenerator.Descriptor descriptor() { return new AttachmentGenerator.Descriptor(Map.of(), "https://fixture.invalid/synthetic"); }
  java.net.URL signedUrl() throws Exception {
    String date = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC).format(fixture.flow.http.clock.instant());
    return URI.create("https://storage.googleapis.com/private-avatars/" + KEY
        + "?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=fixture&X-Goog-Date=" + date
        + "&X-Goog-Expires=300&X-Goog-SignedHeaders=host&X-Goog-Signature=00&generation=42").toURL();
  }
  Object upload() throws Exception { return attachments.getAttachmentUploadForm(principal, Optional.of(100L), "synthetic"); }
  Object download() throws Exception { return media.getDownload(principal, new MediaDownloadController.DownloadRequest(0, KEY)); }
  void httpFailure(int status, org.junit.jupiter.api.function.Executable operation) {
    assertThat(assertThrows(WebApplicationException.class, operation).getResponse().getStatus()).isEqualTo(status);
  }
  void expire() { fixture.flow.http.advance(4000); }
  void suspend() { fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp()"); }
  void neverSigns() { verify(storage, never()).signUrl(any(BlobInfo.class), anyLong(), any(TimeUnit.class), any(Storage.SignUrlOption[].class)); }
  ContainerResponse request(String path, String method, Object body) throws Exception {
    var request = new ContainerRequest(URI.create("http://localhost/"), URI.create("http://localhost" + path), method,
        mock(jakarta.ws.rs.core.SecurityContext.class), new MapPropertiesDelegate(), null);
    request.header("Authorization", HeaderUtils.basicAuthHeader(fixture.aci.toString(), fixture.flow.input.password()));
    if (body != null) {
      request.header("Content-Type", "application/json");
      request.setEntityStream(new java.io.ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(body)));
    }
    return jersey.apply(request).get(5, TimeUnit.SECONDS);
  }
  org.signal.chat.attachments.GetUploadFormResponse grpcUpload() {
    return grpc.getUploadForm(org.signal.chat.attachments.GetUploadFormRequest.newBuilder().setUploadLength(100).build());
  }

  @Test void prooflessAndSecondaryCannotIssue() {
    var proof = principal.admissionAuthorization();
    principal = new AuthenticatedDevice(fixture.aci, (byte) 1, principal.primaryDeviceLastSeen());
    httpFailure(401, this::upload); httpFailure(401, this::download);
    principal = new AuthenticatedDevice(fixture.aci, (byte) 2, principal.primaryDeviceLastSeen(), proof);
    httpFailure(401, this::upload); httpFailure(401, this::download);
    verifyNoInteractions(count, bytes, uploads, storage);
  }
  @Test void expiredOriginalProofCannotBorrowNewReceipt() {
    expire(); httpFailure(503, this::upload); httpFailure(503, this::download);
    assertThat(fixture.requests.get()).isEqualTo(1); verifyNoInteractions(count, bytes, uploads, storage);
  }
  @Test void rateLimitWaitConsumesUploadDeadline() throws Exception {
    doAnswer(_ -> { expire(); return null; }).when(count).validate(fixture.aci);
    httpFailure(503, this::upload); verifyNoInteractions(uploads);
  }
  @Test void experimentWaitCannotReachSigner() {
    attachments = new AttachmentControllerV4(rates, uploads, mock(TusAttachmentGenerator.class), experiments, 1024, true);
    when(experiments.isEnrolled(any(UUID.class), anyString())).thenAnswer(_ -> { expire(); return false; });
    httpFailure(503, this::upload); verifyNoInteractions(uploads);
  }
  @Test void expiredUploadSigningResultNotReturned() {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> { expire(); return descriptor(); });
    httpFailure(503, this::upload);
  }
  @Test void suspendedDuringUploadSigningNotReturned() {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> { suspend(); return descriptor(); });
    httpFailure(401, this::upload);
  }
  @Test void uploadCredentialRotationDuringSigningNotReturned() {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> {
      fixture.sql("UPDATE signal.accounts SET version=version+1"); return descriptor();
    });
    httpFailure(503, this::upload);
  }
  @Test void mediaRateLimitWaitCannotReachStorage() throws Exception {
    doAnswer(_ -> { expire(); return null; }).when(count).validate(fixture.aci);
    httpFailure(503, this::download); verifyNoInteractions(storage);
  }
  @Test void mediaMetadataWaitCannotReachSigner() {
    when(storage.get(any(BlobId.class))).thenAnswer(_ -> { expire(); return blob; });
    httpFailure(503, this::download); neverSigns();
  }
  @Test void mediaMetadataSuspensionCannotReachSigner() {
    when(storage.get(any(BlobId.class))).thenAnswer(_ -> { suspend(); return blob; });
    httpFailure(401, this::download); neverSigns();
  }
  @Test void mediaSigningExpiryCannotReturnUrl() {
    when(storage.signUrl(any(BlobInfo.class), anyLong(), any(TimeUnit.class), any(Storage.SignUrlOption[].class)))
        .thenAnswer(_ -> { expire(); return signedUrl(); });
    httpFailure(503, this::download);
  }
  @Test void mediaSigningSuspensionCannotReturnUrl() {
    when(storage.signUrl(any(BlobInfo.class), anyLong(), any(TimeUnit.class), any(Storage.SignUrlOption[].class)))
        .thenAnswer(_ -> { suspend(); return signedUrl(); });
    httpFailure(401, this::download);
  }
  @Test void missingObjectAfterExpiryIsUnavailableNotAnExistenceResult() {
    when(storage.get(any(BlobId.class))).thenAnswer(_ -> { expire(); return null; });
    httpFailure(503, this::download); neverSigns();
  }
  @Test void actualHttpRoutesReturnCapabilitiesOnlyWithCurrentProof() throws Exception {
    assertThat(request("/v4/attachments/form/upload?uploadLength=100", "GET", null).getStatus()).isEqualTo(200);
    var response = request("/v1/media/download", "POST", new MediaDownloadController.DownloadRequest(0, KEY));
    assertThat(response.getStatus()).isEqualTo(200); assertThat(response.getHeaderString("Cache-Control")).contains("no-store");
  }
  @Test void actualHttpRouteSuppressesLateSignerResult() throws Exception {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> { expire(); return descriptor(); });
    assertThat(request("/v4/attachments/form/upload?uploadLength=100", "GET", null).getStatus()).isEqualTo(503);
  }
  @Test void actualGrpcRateWaitCannotReachSigner() throws Exception {
    doAnswer(_ -> { expire(); return null; }).when(count).validate(fixture.aci);
    assertThat(assertThrows(StatusRuntimeException.class, this::grpcUpload).getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(uploads);
  }
  @Test void actualGrpcSignerSuspensionDeniesCapability() {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> { suspend(); return descriptor(); });
    assertThat(assertThrows(StatusRuntimeException.class, this::grpcUpload).getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
  }
  @Test void actualGrpcSignerExpiryIsUnavailable() {
    when(uploads.generateAttachment(any(), anyLong())).thenAnswer(_ -> { expire(); return descriptor(); });
    assertThat(assertThrows(StatusRuntimeException.class, this::grpcUpload).getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }
  @Test void actualGrpcFreshProofReturnsCapability() { assertThat(grpcUpload().hasUploadForm()).isTrue(); }
  @Test void providerFailureDoesNotExposeDetailsOnEitherTransport() throws Exception {
    when(uploads.generateAttachment(any(), anyLong())).thenThrow(new IllegalStateException("secret-signed-url"));
    var response = request("/v4/attachments/form/upload?uploadLength=100", "GET", null);
    assertThat(response.getStatus()).isEqualTo(503); assertThat(String.valueOf(response.getEntity())).doesNotContain("secret-signed-url");
    var failure = assertThrows(StatusRuntimeException.class, this::grpcUpload);
    assertThat(failure.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    assertThat(failure.getMessage()).doesNotContain("secret-signed-url");
  }
}
