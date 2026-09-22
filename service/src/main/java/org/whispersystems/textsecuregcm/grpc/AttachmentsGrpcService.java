/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.grpc;

import org.whispersystems.textsecuregcm.admission.AdmissionCapabilityGuard;
import java.security.SecureRandom;
import java.util.Map;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import org.signal.chat.attachments.GetStickerUploadFormRequest;
import org.signal.chat.attachments.GetStickerUploadFormResponse;
import org.signal.chat.attachments.GetUploadFormRequest;
import org.signal.chat.attachments.GetUploadFormResponse;
import org.signal.chat.attachments.SimpleAttachmentsGrpc;
import org.signal.chat.common.UploadForm;
import org.signal.chat.errors.FailedPrecondition;
import org.whispersystems.textsecuregcm.attachments.AttachmentGenerator;
import org.whispersystems.textsecuregcm.attachments.AttachmentUtil;
import org.whispersystems.textsecuregcm.attachments.GcsAttachmentGenerator;
import org.whispersystems.textsecuregcm.attachments.TusAttachmentGenerator;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.grpc.AuthenticationUtil;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.metrics.UserAgentTagUtil;

public class AttachmentsGrpcService extends SimpleAttachmentsGrpc.AttachmentsImplBase {

  private final boolean requireCurrentMembership;

  private final ExperimentEnrollmentManager experimentEnrollmentManager;
  private final RateLimiter countRateLimiter;
  private final RateLimiter bytesRateLimiter;
  private final long maxUploadLength;
  private final Map<Integer, AttachmentGenerator> attachmentGenerators;
  private final SecureRandom secureRandom;

  private static final String ATTACHMENT_SIZE_NAME =
      MetricsUtil.name(AttachmentsGrpcService.class, "attachmentSize");

  public AttachmentsGrpcService(
      final ExperimentEnrollmentManager experimentEnrollmentManager,
      final RateLimiters rateLimiters,
      final GcsAttachmentGenerator gcsAttachmentGenerator,
      final TusAttachmentGenerator tusAttachmentGenerator,
      final long maxUploadLength) {
    this(experimentEnrollmentManager, rateLimiters, gcsAttachmentGenerator, tusAttachmentGenerator, maxUploadLength, false);
  }

  public AttachmentsGrpcService(
      final ExperimentEnrollmentManager experimentEnrollmentManager,
      final RateLimiters rateLimiters,
      final GcsAttachmentGenerator gcsAttachmentGenerator,
      final TusAttachmentGenerator tusAttachmentGenerator,
      final long maxUploadLength,
      final boolean requireCurrentMembership) {
    this.requireCurrentMembership = requireCurrentMembership;
    this.experimentEnrollmentManager = experimentEnrollmentManager;
    this.countRateLimiter = rateLimiters.getAttachmentLimiter();
    this.bytesRateLimiter = rateLimiters.getAttachmentBytesLimiter();
    this.maxUploadLength = maxUploadLength;
    this.secureRandom = new SecureRandom();
    this.attachmentGenerators = tusAttachmentGenerator == null ? Map.of(2, gcsAttachmentGenerator)
        : Map.of(2, gcsAttachmentGenerator, 3, tusAttachmentGenerator);
  }

  @Override
  public GetUploadFormResponse getUploadForm(final GetUploadFormRequest request) throws RateLimitExceededException {
    if (request.getUploadLength() > maxUploadLength) {
      return GetUploadFormResponse.newBuilder()
          .setExceedsMaxUploadLength(FailedPrecondition.getDefaultInstance())
          .build();
    }
    final AuthenticatedDevice auth = AuthenticationUtil.requireAuthenticatedDevice();
    final Runnable authorization = AdmissionCapabilityGuard.grpc(auth, requireCurrentMembership);
    authorization.run();

    countRateLimiter.validate(auth.accountIdentifier());
    try {
      // Ideally we'd check these two rate limits transactionally and only update them if both permits were acquired.
      // However, just undoing the first modification if the second one fails is close enough for our purposes
      bytesRateLimiter.validate(auth.accountIdentifier(), request.getUploadLength());
    } catch (RateLimitExceededException e) {
      countRateLimiter.restorePermits(auth.accountIdentifier(), 1);
      throw e;
    }

    DistributionSummary.builder(ATTACHMENT_SIZE_NAME)
        .tags(Tags.of(UserAgentTagUtil.getPlatformTag(RequestAttributesUtil.getUserAgent().orElse(null))))
        .register(Metrics.globalRegistry)
        .record(request.getUploadLength());

    authorization.run();
    final String key = AttachmentUtil.generateAttachmentKey(secureRandom);
    final boolean useCdn3 = attachmentGenerators.containsKey(3) && this.experimentEnrollmentManager.isEnrolled(auth.accountIdentifier(),
        AttachmentUtil.CDN3_EXPERIMENT_NAME);
    final int cdn = useCdn3 ? 3 : 2;
    authorization.run();
    final AttachmentGenerator.Descriptor descriptor;
    try { descriptor = this.attachmentGenerators.get(cdn).generateAttachment(key, request.getUploadLength()); }
    catch (RuntimeException providerFailure) { throw GrpcExceptions.unavailable(); }
    authorization.run();
    return GetUploadFormResponse.newBuilder().setUploadForm(UploadForm.newBuilder()
        .setCdn(cdn)
        .setKey(key)
        .putAllHeaders(descriptor.headers())
        .setSignedUploadLocation(descriptor.signedUploadLocation()))
        .build();
  }

  @Override
  public GetStickerUploadFormResponse getStickerUploadForm(final GetStickerUploadFormRequest request) {
    throw GrpcExceptions.unavailable("Sticker uploads are unavailable in this runtime");
  }
}
