// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.mappers;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;

public class FeatureUnavailableExceptionMapper implements ExceptionMapper<FeatureUnavailableException> {
  @Override
  public Response toResponse(final FeatureUnavailableException exception) {
    return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
  }
}
