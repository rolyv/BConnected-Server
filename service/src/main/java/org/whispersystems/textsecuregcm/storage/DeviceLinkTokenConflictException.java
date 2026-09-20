// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;
/** A replay marker already exists; the surrounding account transaction has rolled back. */
public final class DeviceLinkTokenConflictException extends RuntimeException {}
