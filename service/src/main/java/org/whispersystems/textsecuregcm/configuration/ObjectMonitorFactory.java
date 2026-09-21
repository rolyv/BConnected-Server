/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.dropwizard.jackson.Discoverable;
import org.whispersystems.textsecuregcm.monitoring.ObjectMonitor;
import java.util.concurrent.ScheduledExecutorService;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
public interface ObjectMonitorFactory extends Discoverable {

  ObjectMonitor build(ScheduledExecutorService refreshExecutorService);
}
