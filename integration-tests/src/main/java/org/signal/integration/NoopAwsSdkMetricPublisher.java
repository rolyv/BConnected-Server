// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.signal.integration;

import software.amazon.awssdk.metrics.MetricCollection;
import software.amazon.awssdk.metrics.MetricPublisher;

/** Fixture for the excluded integration harness; never packaged in the server runtime. */
final class NoopAwsSdkMetricPublisher implements MetricPublisher {

  @Override
  public void publish(final MetricCollection metricCollection) {
  }

  @Override
  public void close() {
  }
}
