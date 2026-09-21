/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.server.DefaultServerFactory;
import io.dropwizard.jetty.HttpsConnectorFactory;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.whispersystems.textsecuregcm.attachments.TusConfiguration;
import org.whispersystems.textsecuregcm.configuration.ApnConfiguration;
import org.whispersystems.textsecuregcm.configuration.AppleAppStoreConfiguration;
import org.whispersystems.textsecuregcm.configuration.AppleDeviceCheckConfiguration;
import org.whispersystems.textsecuregcm.configuration.AttachmentsConfiguration;
import org.whispersystems.textsecuregcm.configuration.AwsCredentialsProviderFactory;
import org.whispersystems.textsecuregcm.configuration.BackupConfiguration;
import org.whispersystems.textsecuregcm.configuration.BadgesConfiguration;
import org.whispersystems.textsecuregcm.configuration.BraintreeConfiguration;
import org.whispersystems.textsecuregcm.configuration.CallQualitySurveyConfiguration;
import org.whispersystems.textsecuregcm.configuration.Cdn3StorageManagerConfiguration;
import org.whispersystems.textsecuregcm.configuration.CdnConfiguration;
import org.whispersystems.textsecuregcm.configuration.ChangeNumberConfiguration;
import org.whispersystems.textsecuregcm.configuration.CircuitBreakerConfiguration;
import org.whispersystems.textsecuregcm.configuration.ClientReleaseConfiguration;
import org.whispersystems.textsecuregcm.configuration.DefaultAwsCredentialsFactory;
import org.whispersystems.textsecuregcm.configuration.DeviceCheckConfiguration;
import org.whispersystems.textsecuregcm.configuration.DirectoryV2Configuration;
import org.whispersystems.textsecuregcm.configuration.DynamoDbClientFactory;
import org.whispersystems.textsecuregcm.configuration.DynamoDbTables;
import org.whispersystems.textsecuregcm.configuration.ExternalRequestFilterConfiguration;
import org.whispersystems.textsecuregcm.configuration.FaultTolerantRedisClientFactory;
import org.whispersystems.textsecuregcm.configuration.FaultTolerantRedisClusterFactory;
import org.whispersystems.textsecuregcm.configuration.FcmConfiguration;
import org.whispersystems.textsecuregcm.configuration.FoundationDbMessagesConfiguration;
import org.whispersystems.textsecuregcm.configuration.GcpAttachmentsConfiguration;
import org.whispersystems.textsecuregcm.configuration.GcsAvatarConfiguration;
import org.whispersystems.textsecuregcm.configuration.GcsMediaDownloadConfiguration;
import org.whispersystems.textsecuregcm.configuration.GenericZkConfig;
import org.whispersystems.textsecuregcm.configuration.GooglePlayBillingConfiguration;
import org.whispersystems.textsecuregcm.configuration.GrpcConfiguration;
import org.whispersystems.textsecuregcm.configuration.HlrLookupConfiguration;
import org.whispersystems.textsecuregcm.configuration.IdlePrimaryDeviceReminderConfiguration;
import org.whispersystems.textsecuregcm.configuration.KeyTransparencyServiceConfiguration;
import org.whispersystems.textsecuregcm.configuration.LinkDeviceSecretConfiguration;
import org.whispersystems.textsecuregcm.configuration.LoginPurchaseConfiguration;
import org.whispersystems.textsecuregcm.configuration.MessageByteLimitCardinalityEstimatorConfiguration;
import org.whispersystems.textsecuregcm.configuration.MessageCacheConfiguration;
import org.whispersystems.textsecuregcm.configuration.MonitoredFileObjectConfiguration;
import org.whispersystems.textsecuregcm.configuration.OneTimeDonationConfiguration;
import org.whispersystems.textsecuregcm.configuration.OpenTelemetryConfiguration;
import org.whispersystems.textsecuregcm.configuration.PagedSingleUseKEMPreKeyStoreConfiguration;
import org.whispersystems.textsecuregcm.configuration.PaymentsServiceConfiguration;
import org.whispersystems.textsecuregcm.configuration.PilotIntegrationsConfiguration;
import org.whispersystems.textsecuregcm.configuration.RegistrationServiceClientFactory;
import org.whispersystems.textsecuregcm.configuration.RemoteConfigConfiguration;
import org.whispersystems.textsecuregcm.configuration.ReportMessageConfiguration;
import org.whispersystems.textsecuregcm.configuration.RetryConfiguration;
import org.whispersystems.textsecuregcm.configuration.RuntimeMode;
import org.whispersystems.textsecuregcm.configuration.ObjectMonitorFactory;
import org.whispersystems.textsecuregcm.configuration.SecureStorageServiceConfiguration;
import org.whispersystems.textsecuregcm.configuration.SecureValueRecoveryConfiguration;
import org.whispersystems.textsecuregcm.configuration.ShortCodeExpanderConfiguration;
import org.whispersystems.textsecuregcm.configuration.SpamFilterConfiguration;
import org.whispersystems.textsecuregcm.configuration.StripeConfiguration;
import org.whispersystems.textsecuregcm.configuration.SubscriptionConfiguration;
import org.whispersystems.textsecuregcm.configuration.TelnyxRegistrationServiceConfiguration;
import org.whispersystems.textsecuregcm.configuration.TlsKeyStoreConfiguration;
import org.whispersystems.textsecuregcm.configuration.TotpConfiguration;
import org.whispersystems.textsecuregcm.configuration.TurnConfiguration;
import org.whispersystems.textsecuregcm.configuration.UnidentifiedDeliveryConfiguration;
import org.whispersystems.textsecuregcm.configuration.VirtualThreadConfiguration;
import org.whispersystems.textsecuregcm.configuration.WebAuthnConfiguration;
import org.whispersystems.textsecuregcm.configuration.ZkConfig;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.websocket.configuration.WebSocketConfiguration;

// @noinspection MismatchedQueryAndUpdateOfCollection, WeakerAccess
public class WhisperServerConfiguration extends Configuration {

  @NotNull @JsonProperty
  private RuntimeMode runtimeMode = RuntimeMode.LEGACY;

  @Valid @JsonProperty
  private GcsAvatarConfiguration gcpAvatars;

  @Valid @NotNull @JsonProperty
  private PilotIntegrationsConfiguration pilotIntegrations =
      PilotIntegrationsConfiguration.DISABLED;

  public boolean isApnsEnabled() { return !isGcpPilot() || pilotIntegrations.apnsEnabled(); }
  public boolean isFcmEnabled() { return !isGcpPilot() || pilotIntegrations.fcmEnabled(); }
  public boolean isStorageEnabled() { return !isGcpPilot() || pilotIntegrations.storageEnabled(); }
  public boolean isSvr2Enabled() { return !isGcpPilot() || pilotIntegrations.svr2Enabled(); }

  public Set<PushNotification.TokenType> enabledPushTypes() {
    final var enabled = EnumSet.noneOf(PushNotification.TokenType.class);
    if (isApnsEnabled()) enabled.add(PushNotification.TokenType.APN);
    if (isFcmEnabled()) enabled.add(PushNotification.TokenType.FCM);
    return Set.copyOf(enabled);
  }

  public RuntimeMode getRuntimeMode() { return runtimeMode; }
  public boolean isGcpPilot() { return runtimeMode == RuntimeMode.GCP_PILOT; }
  public GcsAvatarConfiguration getGcpAvatars() { return gcpAvatars; }
  @Valid @JsonProperty
  private GcsMediaDownloadConfiguration gcpMediaDownloads;
  public GcsMediaDownloadConfiguration getGcpMediaDownloads() {
    return gcpMediaDownloads;
  }

  public Duration getMessageRetention() {
    return postgres.messageRetention();
  }

  public Duration getRecoveryRetention() {
    return postgres.recoveryRetention();
  }

  @AssertTrue(message = "Runtime mode dependencies are missing or incompatible")
  @JsonIgnore
  public boolean isRuntimeConfigurationValid() { return runtimeConfigurationErrors().isEmpty(); }

  public void validateRuntimeConfiguration() {
    final List<String> errors = runtimeConfigurationErrors();
    if (!errors.isEmpty()) throw new IllegalArgumentException(String.join("; ", errors));
  }

  private boolean requiresTlsKeyStore() {
    if (!isGcpPilot() || grpc == null || !grpc.h2c()) return true;
    if (getServerFactory() instanceof DefaultServerFactory server) {
      return java.util.stream.Stream.concat(server.getApplicationConnectors().stream(), server.getAdminConnectors().stream())
          .anyMatch(HttpsConnectorFactory.class::isInstance);
    }
    return true;
  }

  private List<String> runtimeConfigurationErrors() {
    final List<String> errors = new ArrayList<>();
    if (runtimeMode == null) errors.add("runtimeMode is required");
    if (pilotIntegrations == null) {
      errors.add("pilotIntegrations must not be null");
      return errors;
    }
    if (tlsKeyStore == null && requiresTlsKeyStore()) errors.add("TLS listeners require tlsKeyStore configuration");
    if (isApnsEnabled() && apn == null) errors.add("Enabled APNs requires apn configuration");
    if (isFcmEnabled() && fcm == null) errors.add("Enabled FCM requires fcm configuration");
    if (isStorageEnabled() && storageService == null) errors.add("Enabled storage requires storageService configuration");
    if (isSvr2Enabled() && svr2 == null) errors.add("Enabled SVR2 requires svr2 configuration");
    if (postgres == null || postgres.messageRetention() == null || postgres.recoveryRetention() == null)
      errors.add("All runtime modes require PostgreSQL with explicit messageRetention and recoveryRetention");
    if (isGcpPilot()) {
      if (!(dynamicConfig instanceof MonitoredFileObjectConfiguration) || !(asnTable instanceof MonitoredFileObjectConfiguration))
        errors.add("GCP_PILOT requires type:file dynamicConfig and asnTable sources");
      if (!(registrationService instanceof TelnyxRegistrationServiceConfiguration))
        errors.add("GCP_PILOT requires type:telnyx registrationService");
      if (gcpAvatars == null) errors.add("GCP_PILOT requires gcpAvatars");
      if (gcpAttachments == null || !gcpAttachments.useIamSigning() || !gcpAttachments.isSigningConfigurationValid())
        errors.add("GCP_PILOT requires IAM signing for attachments");
    } else {
      final Object[] legacy = {stripe, braintree, googlePlayBilling, appleAppStore, appleDeviceCheck, deviceCheck,
          dynamoDbClient, dynamoDbTables, cdn, cdn3StorageManager, svrb, paymentsService, subscription, oneTimeDonations,
          loginPurchase, pagedSingleUseKEMPreKeyStore, turn, tus, callQualitySurvey, foundationDbMessages,
          callingZkConfig, callingZkConfigPreV101, keyTransparencyService, hlrLookup};
      if (java.util.Arrays.stream(legacy).anyMatch(java.util.Objects::isNull))
        errors.add("LEGACY runtime requires billing, backup, calling, CDN, DynamoDB, FoundationDB and Key Transparency configuration");
    }
    return errors;
  }

  @NotNull
  @Valid
  @JsonProperty
  private org.whispersystems.textsecuregcm.configuration.PostgresConfiguration postgres;

  public org.whispersystems.textsecuregcm.configuration.PostgresConfiguration getPostgresConfiguration() {
    return postgres;
  }

  @Valid
  @JsonProperty
  private TlsKeyStoreConfiguration tlsKeyStore;

  @NotNull
  @Valid
  @JsonProperty
  AwsCredentialsProviderFactory awsCredentialsProvider = new DefaultAwsCredentialsFactory();

  @Valid
  @JsonProperty
  private StripeConfiguration stripe;

  @Valid
  @JsonProperty
  private BraintreeConfiguration braintree;

  @Valid
  @JsonProperty
  private GooglePlayBillingConfiguration googlePlayBilling;

  @Valid
  @JsonProperty
  private AppleAppStoreConfiguration appleAppStore;

  @Valid
  @JsonProperty
  private AppleDeviceCheckConfiguration appleDeviceCheck;

  @Valid
  @JsonProperty
  private DeviceCheckConfiguration deviceCheck;

  @Valid
  @JsonProperty
  private DynamoDbClientFactory dynamoDbClient;

  @Valid
  @JsonProperty
  private DynamoDbTables dynamoDbTables;

  @NotNull
  @Valid
  @JsonProperty
  private AttachmentsConfiguration attachments;

  @NotNull
  @Valid
  @JsonProperty
  private GcpAttachmentsConfiguration gcpAttachments;

  @NotNull
  @Valid
  @JsonProperty
  private BackupConfiguration backup = new BackupConfiguration();

  @Valid
  @JsonProperty
  private CdnConfiguration cdn;

  @Valid
  @JsonProperty
  private Cdn3StorageManagerConfiguration cdn3StorageManager;

  @NotNull
  @Valid
  @JsonProperty
  private OpenTelemetryConfiguration openTelemetry;

  @NotNull
  @Valid
  @JsonProperty
  private FaultTolerantRedisClusterFactory cacheCluster;

  @NotNull
  @Valid
  @JsonProperty
  private FaultTolerantRedisClientFactory pubsub;

  @NotNull
  @Valid
  @JsonProperty
  private DirectoryV2Configuration directoryV2;

  @Valid
  @JsonProperty
  private SecureValueRecoveryConfiguration svr2;

  @Valid
  @JsonProperty
  private SecureValueRecoveryConfiguration svrb;

  @NotNull
  @Valid
  @JsonProperty
  private FaultTolerantRedisClusterFactory pushSchedulerCluster;

  @NotNull
  @Valid
  @JsonProperty
  private FaultTolerantRedisClusterFactory rateLimitersCluster;

  @NotNull
  @Valid
  @JsonProperty
  private MessageCacheConfiguration messageCache;

  @Valid
  @NotNull
  @JsonProperty
  private WebSocketConfiguration webSocket = new WebSocketConfiguration();

  @Valid
  @JsonProperty
  private FcmConfiguration fcm;

  @Valid
  @JsonProperty
  private ApnConfiguration apn;

  @Valid
  @NotNull
  @JsonProperty
  private UnidentifiedDeliveryConfiguration unidentifiedDelivery;

  @Valid
  @NotNull
  @JsonProperty
  private ShortCodeExpanderConfiguration shortCode;

  @Valid
  @JsonProperty
  private SecureStorageServiceConfiguration storageService;

  @Valid
  @JsonProperty
  private PaymentsServiceConfiguration paymentsService;

  @Valid
  @JsonProperty
  private GenericZkConfig callingZkConfigPreV101;

  @Valid
  @JsonProperty
  private GenericZkConfig callingZkConfig;

  @Valid
  @NotNull
  @JsonProperty
  private GenericZkConfig chatZkConfig;

  @Valid
  @NotNull
  @JsonProperty
  private ZkConfig groupsZkConfig;

  @Valid
  @NotNull
  @JsonProperty
  private RemoteConfigConfiguration remoteConfig;

  @Valid
  @NotNull
  @JsonProperty
  private ObjectMonitorFactory dynamicConfig;

  @Valid
  @NotNull
  @JsonProperty
  private BadgesConfiguration badges;

  @Valid
  @JsonProperty
  private SubscriptionConfiguration subscription;

  @Valid
  @JsonProperty
  private OneTimeDonationConfiguration oneTimeDonations;

  @Valid
  @JsonProperty
  private LoginPurchaseConfiguration loginPurchase;

  @Valid
  @JsonProperty
  private PagedSingleUseKEMPreKeyStoreConfiguration pagedSingleUseKEMPreKeyStore;

  @Valid
  @NotNull
  @JsonProperty
  private ReportMessageConfiguration reportMessage = new ReportMessageConfiguration();

  @Valid
  @JsonProperty
  private SpamFilterConfiguration spamFilter;

  @Valid
  @NotNull
  @JsonProperty
  private RegistrationServiceClientFactory registrationService;

  @Valid
  @JsonProperty
  private TurnConfiguration turn;

  @Valid
  @JsonProperty
  private TusConfiguration tus;

  @Valid
  @NotNull
  @JsonProperty
  private ClientReleaseConfiguration clientRelease = new ClientReleaseConfiguration(Duration.ofHours(4));

  @Valid
  @NotNull
  @JsonProperty
  private MessageByteLimitCardinalityEstimatorConfiguration messageByteLimitCardinalityEstimator = new MessageByteLimitCardinalityEstimatorConfiguration(Duration.ofDays(1));

  @Valid
  @NotNull
  @JsonProperty
  private LinkDeviceSecretConfiguration linkDevice;

  @Valid
  @NotNull
  @JsonProperty
  private VirtualThreadConfiguration virtualThread = new VirtualThreadConfiguration();

  @Valid
  @NotNull
  @JsonProperty
  private ExternalRequestFilterConfiguration externalRequestFilter;

  @Valid
  @JsonProperty
  private KeyTransparencyServiceConfiguration keyTransparencyService;

  @JsonProperty
  private boolean logMessageDeliveryLoops;

  @JsonProperty
  private IdlePrimaryDeviceReminderConfiguration idlePrimaryDeviceReminder =
      new IdlePrimaryDeviceReminderConfiguration(Duration.ofDays(30));

  @JsonProperty
  private Map<String, @Valid CircuitBreakerConfiguration> circuitBreakers = Collections.emptyMap();

  @JsonProperty
  private Map<String, @Valid RetryConfiguration> retries = Collections.emptyMap();

  @Valid
  @JsonProperty
  private HlrLookupConfiguration hlrLookup;

  @JsonProperty
  @Valid
  @NotNull
  private RetryConfiguration generalRedisRetry = new RetryConfiguration();

  @NotNull
  @Valid
  @JsonProperty
  private GrpcConfiguration grpc;

  @Valid
  @NotNull
  @JsonProperty
  private ObjectMonitorFactory asnTable;

  @Valid
  @JsonProperty
  private CallQualitySurveyConfiguration callQualitySurvey;

  @Valid
  @NotNull
  @JsonProperty
  private ChangeNumberConfiguration changeNumber = new ChangeNumberConfiguration(Duration.ofHours(1));

  @Valid
  @JsonProperty
  private FoundationDbMessagesConfiguration foundationDbMessages;

  @Valid
  @NotNull
  @JsonProperty
  private TotpConfiguration registrationTotp = TotpConfiguration.DEFAULT;

  @Valid
  @NotNull
  @JsonProperty
  private WebAuthnConfiguration registrationWebAuthn;

  public TlsKeyStoreConfiguration getTlsKeyStoreConfiguration() {
    return tlsKeyStore;
  }

  public AwsCredentialsProviderFactory getAwsCredentialsConfiguration() {
    return awsCredentialsProvider;
  }

  public StripeConfiguration getStripe() {
    return stripe;
  }

  public BraintreeConfiguration getBraintree() {
    return braintree;
  }

  public GooglePlayBillingConfiguration getGooglePlayBilling() {
    return googlePlayBilling;
  }

  public AppleAppStoreConfiguration getAppleAppStore() {
    return appleAppStore;
  }

  public AppleDeviceCheckConfiguration getAppleDeviceCheck() {
    return appleDeviceCheck;
  }

  public DeviceCheckConfiguration getDeviceCheck() {
    return deviceCheck;
  }

  public DynamoDbClientFactory getDynamoDbClientConfiguration() {
    return dynamoDbClient;
  }

  public DynamoDbTables getDynamoDbTables() {
    return dynamoDbTables;
  }

  public ShortCodeExpanderConfiguration getShortCodeRetrieverConfiguration() {
    return shortCode;
  }

  public WebSocketConfiguration getWebSocketConfiguration() {
    return webSocket;
  }

  public AttachmentsConfiguration getAttachments() {
    return attachments;
  }

  public GcpAttachmentsConfiguration getGcpAttachmentsConfiguration() {
    return gcpAttachments;
  }

  public BackupConfiguration getBackupConfiguration() {
    return backup;
  }

  public FaultTolerantRedisClusterFactory getCacheClusterConfiguration() {
    return cacheCluster;
  }

  public FaultTolerantRedisClientFactory getRedisPubSubConfiguration() {
    return pubsub;
  }

  public SecureValueRecoveryConfiguration getSvr2Configuration() {
    return svr2;
  }

  public SecureValueRecoveryConfiguration getSvrbConfiguration() {
    return svrb;
  }

  public DirectoryV2Configuration getDirectoryV2Configuration() {
    return directoryV2;
  }

  public SecureStorageServiceConfiguration getSecureStorageServiceConfiguration() {
    return storageService;
  }

  public MessageCacheConfiguration getMessageCacheConfiguration() {
    return messageCache;
  }

  public FaultTolerantRedisClusterFactory getPushSchedulerCluster() {
    return pushSchedulerCluster;
  }

  public FaultTolerantRedisClusterFactory getRateLimitersCluster() {
    return rateLimitersCluster;
  }

  public FcmConfiguration getFcmConfiguration() {
    return fcm;
  }

  public ApnConfiguration getApnConfiguration() {
    return apn;
  }

  public CdnConfiguration getCdnConfiguration() {
    return cdn;
  }

  public Cdn3StorageManagerConfiguration getCdn3StorageManagerConfiguration() {
    return cdn3StorageManager;
  }

  public OpenTelemetryConfiguration getOpenTelemetryConfiguration() {
    return openTelemetry;
  }

  public UnidentifiedDeliveryConfiguration getDeliveryCertificate() {
    return unidentifiedDelivery;
  }

  public PaymentsServiceConfiguration getPaymentsServiceConfiguration() {
    return paymentsService;
  }

  /// ZK secret limited to Chat Service
  public GenericZkConfig getChatZkConfig() {
    return chatZkConfig;
  }

  /// ZK secret shared with Calling Service
  public GenericZkConfig getCallingZkConfigPreV101() {
    return callingZkConfigPreV101;
  }

  /// ZK secret shared with Calling Service
  public GenericZkConfig getCallingZkConfig() {
    return callingZkConfig;
  }

  /// ZK secret shared with Groups Service
  public ZkConfig getGroupsZkConfig() {
    return groupsZkConfig;
  }

  public RemoteConfigConfiguration getRemoteConfigConfiguration() {
    return remoteConfig;
  }

  public ObjectMonitorFactory getDynamicConfig() {
    return dynamicConfig;
  }

  public BadgesConfiguration getBadges() {
    return badges;
  }

  public SubscriptionConfiguration getSubscription() {
    return subscription;
  }

  public OneTimeDonationConfiguration getOneTimeDonations() {
    return oneTimeDonations;
  }

  public LoginPurchaseConfiguration getLoginPurchase() {
    return loginPurchase;
  }

  public PagedSingleUseKEMPreKeyStoreConfiguration getPagedSingleUseKEMPreKeyStore() {
    return pagedSingleUseKEMPreKeyStore;
  }

  public ReportMessageConfiguration getReportMessageConfiguration() {
    return reportMessage;
  }

  public SpamFilterConfiguration getSpamFilterConfiguration() {
    return spamFilter;
  }

  public RegistrationServiceClientFactory getRegistrationServiceConfiguration() {
    return registrationService;
  }

  public TurnConfiguration getTurnConfiguration() {
    return turn;
  }

  public TusConfiguration getTus() {
    return tus;
  }

  public ClientReleaseConfiguration getClientReleaseConfiguration() {
    return clientRelease;
  }

  public MessageByteLimitCardinalityEstimatorConfiguration getMessageByteLimitCardinalityEstimator() {
    return messageByteLimitCardinalityEstimator;
  }

  public LinkDeviceSecretConfiguration getLinkDeviceSecretConfiguration() {
    return linkDevice;
  }

  public VirtualThreadConfiguration getVirtualThreadConfiguration() {
    return virtualThread;
  }

  public ExternalRequestFilterConfiguration getExternalRequestFilterConfiguration() {
    return externalRequestFilter;
  }

  public KeyTransparencyServiceConfiguration getKeyTransparencyServiceConfiguration() {
    return keyTransparencyService;
  }

  public boolean logMessageDeliveryLoops() {
    return logMessageDeliveryLoops;
  }

  public IdlePrimaryDeviceReminderConfiguration idlePrimaryDeviceReminderConfiguration() {
    return idlePrimaryDeviceReminder;
  }

  public Map<String, CircuitBreakerConfiguration> getCircuitBreakerConfigurations() {
    return circuitBreakers;
  }

  public Map<String, RetryConfiguration> getRetryConfigurations() {
    return retries;
  }

  public RetryConfiguration getGeneralRedisRetryConfiguration() {
    return generalRedisRetry;
  }

  public GrpcConfiguration getGrpc() {
    return grpc;
  }

  public ObjectMonitorFactory getAsnTableConfiguration() {
    return asnTable;
  }

  public CallQualitySurveyConfiguration getCallQualitySurveyConfiguration() {
    return callQualitySurvey;
  }

  public HlrLookupConfiguration getHlrLookupConfiguration() {
    return hlrLookup;
  }

  public ChangeNumberConfiguration getChangeNumber() {
    return changeNumber;
  }

  public FoundationDbMessagesConfiguration getFoundationDbMessagesConfiguration() {
    return foundationDbMessages;
  }

  public TotpConfiguration getRegistrationTotpConfiguration() {
    return registrationTotp;
  }

  public WebAuthnConfiguration getRegistrationWebAuthnConfiguration() {
    return registrationWebAuthn;
  }
}
