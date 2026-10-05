// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import io.dropwizard.servlets.tasks.Task;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Only the existing loopback admin connector registers this operator execution path. */
public final class AccountRecoveryTask extends Task {
  private final AccountRecoveryService service;

  public AccountRecoveryTask(AccountRecoveryService service) {
    super("recover-account");
    this.service = service;
  }

  @Override
  public void execute(Map<String, List<String>> parameters, PrintWriter out) {
    if (!parameters.keySet().equals(Set.of("recoveryId", "requestHash"))
        || parameters.values().stream().anyMatch(v -> v.size() != 1)) {
      out.println("INVALID_REQUEST");
      return;
    }
    try {
      String raw = parameters.get("recoveryId").getFirst();
      UUID id = UUID.fromString(raw);
      if (!raw.equals(id.toString())) throw new IllegalArgumentException();
      var result = service.completeOperator(id, parameters.get("requestHash").getFirst());
      if (result.body() instanceof AccountRecoveryService.Observation observation)
        out.println("status=" + result.status() + " state=" + observation.state());
      else if (result.body()
          instanceof
          org.whispersystems.textsecuregcm.admission.enrollment.MobileEnrollmentResponse.Error
              error) out.println("status=" + result.status() + " code=" + error.code());
      else out.println("TEMPORARILY_UNAVAILABLE");
    } catch (RuntimeException invalid) {
      out.println("INVALID_REQUEST");
    }
  }
}
