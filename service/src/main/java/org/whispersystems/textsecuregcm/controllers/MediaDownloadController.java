// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Objects;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.admission.AdmissionCapabilityGuard;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.media.GcsMediaDownloadService;

/** GCP-only authenticated, current-member capability issuance; existing URLs are independently expiring bearer capabilities. */
@Path("/v1/media/download")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class MediaDownloadController {
  private final GcsMediaDownloadService downloads;
  private final RateLimiter limiter;

  public MediaDownloadController(GcsMediaDownloadService downloads, RateLimiters rateLimiters) {
    this.downloads = Objects.requireNonNull(downloads);
    this.limiter = Objects.requireNonNull(rateLimiters.getProfileLimiter());
  }

  public record DownloadRequest(int cdn, @NotNull @Size(min = 1, max = 64) String key) {
    @Override public String toString() { return "DownloadRequest[redacted]"; }
  }

  @POST
  public Response getDownload(@Auth AuthenticatedDevice account, @NotNull @Valid DownloadRequest request)
      throws RateLimitExceededException {
    final Runnable authorization = AdmissionCapabilityGuard.http(account, true);
    authorization.run();
    limiter.validate(account.accountIdentifier());
    authorization.run();
    try {
      GcsMediaDownloadService.validateKey(request.cdn(), request.key());
    } catch (IllegalArgumentException e) {
      throw new BadRequestException();
    }
    try {
      final var capability = downloads.issue(request.cdn(), request.key(), authorization);
      authorization.run();
      return Response.ok(capability)
          .header("Cache-Control", "private, no-store")
          .header("Pragma", "no-cache")
          .build();
    } catch (GcsMediaDownloadService.MissingMediaException e) {
      authorization.run();
      throw new NotFoundException();
    } catch (jakarta.ws.rs.WebApplicationException e) {
      throw e;
    } catch (RuntimeException e) {
      // Do not log provider exceptions: a nested message could contain a sensitive object URL or credential.
      throw new ServiceUnavailableException();
    }
  }
}
