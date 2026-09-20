// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.signal.chat.attachments.AttachmentsGrpc;
import org.signal.chat.attachments.GetStickerUploadFormRequest;
import org.signal.chat.attachments.GetUploadFormRequest;
import org.whispersystems.textsecuregcm.attachments.AttachmentGenerator;
import org.whispersystems.textsecuregcm.attachments.GcsAttachmentGenerator;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;

class GcpAttachmentsGrpcServiceTest extends SimpleBaseGrpcTest<AttachmentsGrpcService, AttachmentsGrpc.AttachmentsBlockingStub> {
  private GcsAttachmentGenerator gcs;
  private RateLimiter limiter;

  @Override
  protected AttachmentsGrpcService createServiceBeforeEachTest() {
    gcs = mock(GcsAttachmentGenerator.class);
    when(gcs.generateAttachment(anyString(), anyLong())).thenReturn(
        new AttachmentGenerator.Descriptor(Map.of("x-goog-resumable", "start"), "https://storage.googleapis.com/pilot/test"));
    final ExperimentEnrollmentManager experiments = mock(ExperimentEnrollmentManager.class);
    when(experiments.isEnrolled(any(java.util.UUID.class), anyString())).thenReturn(true);
    limiter = mock(RateLimiter.class);
    final RateLimiters limits = mock(RateLimiters.class);
    when(limits.getAttachmentLimiter()).thenReturn(limiter);
    when(limits.getAttachmentBytesLimiter()).thenReturn(limiter);
    when(limits.getStickerPackLimiter()).thenReturn(limiter);
    return new AttachmentsGrpcService(experiments, limits, gcs, null, null, 1000, Clock.systemUTC());
  }

  @Override
  protected java.util.List<io.grpc.ServerInterceptor> customizeInterceptors(
      final java.util.List<io.grpc.ServerInterceptor> interceptors) {
    if (interceptors.stream().anyMatch(
        org.whispersystems.textsecuregcm.auth.grpc.MockAuthenticationInterceptor.class::isInstance)) return interceptors;
    final var result = new java.util.ArrayList<>(interceptors);
    result.add(new org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor(
        mock(org.whispersystems.textsecuregcm.auth.AccountAuthenticator.class)));
    return result;
  }

  @Test
  void realConfiguredCdnIsUsedEvenWhenRemoteExperimentSelectsUnavailableCdn3() throws Exception {
    final var response = authenticatedServiceStub().getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(42).build());
    assertThat(response.getUploadForm().getCdn()).isEqualTo(2);
    assertThat(response.getUploadForm().getSignedUploadLocation()).isEqualTo("https://storage.googleapis.com/pilot/test");
    verify(gcs).generateAttachment(response.getUploadForm().getKey(), 42);
    verify(limiter).validate(AUTHENTICATED_ACI);
    verify(limiter).validate(AUTHENTICATED_ACI, 42);
  }

  @Test
  void stickerUploadIsExplicitlyUnavailable() {
    final StatusRuntimeException error = assertThrows(StatusRuntimeException.class,
        () -> authenticatedServiceStub().getStickerUploadForm(GetStickerUploadFormRequest.newBuilder().setStickerCount(1).build()));
    assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
  }

  @Test
  void gcpAttachmentUploadsStillRequireAuthentication() {
    final StatusRuntimeException error = assertThrows(StatusRuntimeException.class,
        () -> unauthenticatedServiceStub().getUploadForm(GetUploadFormRequest.newBuilder().setUploadLength(42).build()));
    assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
  }
}
