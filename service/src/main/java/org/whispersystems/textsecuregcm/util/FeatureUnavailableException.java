// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.util;

import io.grpc.StatusRuntimeException;
import org.whispersystems.textsecuregcm.grpc.ConvertibleToGrpcStatus;
import org.whispersystems.textsecuregcm.grpc.GrpcExceptions;

/** An operation requires an integration that this deployment has explicitly disabled. */
public class FeatureUnavailableException extends RuntimeException implements ConvertibleToGrpcStatus {
  public FeatureUnavailableException(final String feature) {
    super(feature + " is unavailable in this runtime");
  }

  @Override
  public StatusRuntimeException toStatusRuntimeException() {
    return GrpcExceptions.unavailable(getMessage());
  }
}
