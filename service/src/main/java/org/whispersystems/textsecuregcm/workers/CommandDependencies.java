/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import com.apple.foundationdb.Database;
import com.apple.foundationdb.FDB;
import com.fasterxml.jackson.databind.DeserializationFeature;
import io.dropwizard.core.setup.Environment;
import io.lettuce.core.resource.ClientResources;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.stream.Collectors;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.receipts.ServerZkReceiptOperations;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.WhisperServerService.ExecutorServiceBuilder;
import org.whispersystems.textsecuregcm.WhisperServerService.ScheduledExecutorServiceBuilder;
import org.whispersystems.textsecuregcm.attachments.TusAttachmentGenerator;
import org.whispersystems.textsecuregcm.auth.DisconnectionRequestManager;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentialsGenerator;
import org.whispersystems.textsecuregcm.auth.webauthn.WebAuthnCeremonyManager;
import org.whispersystems.textsecuregcm.backup.BackupManager;
import org.whispersystems.textsecuregcm.backup.BackupsDb;
import org.whispersystems.textsecuregcm.backup.Cdn3BackupCredentialGenerator;
import org.whispersystems.textsecuregcm.backup.Cdn3RemoteStorageManager;
import org.whispersystems.textsecuregcm.backup.SecureValueRecoveryBCredentialsGeneratorFactory;
import org.whispersystems.textsecuregcm.configuration.FoundationDbExternalClientConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.controllers.SecureStorageController;
import org.whispersystems.textsecuregcm.controllers.SecureValueRecovery2Controller;
import org.whispersystems.textsecuregcm.experiment.ExperimentEnrollmentManager;
import org.whispersystems.textsecuregcm.experiment.PushNotificationExperimentSamples;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.metrics.MetricsUtil;
import org.whispersystems.textsecuregcm.metrics.MicrometerAwsSdkMetricPublisher;
import org.whispersystems.textsecuregcm.push.APNSender;
import org.whispersystems.textsecuregcm.push.FcmSender;
import org.whispersystems.textsecuregcm.push.PushNotificationManager;
import org.whispersystems.textsecuregcm.push.PushNotificationScheduler;
import org.whispersystems.textsecuregcm.push.PushNotificationSender;
import org.whispersystems.textsecuregcm.push.RedisMessageAvailabilityManager;
import org.whispersystems.textsecuregcm.redis.PubSubRedisClient;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.securestorage.SecureStorageClient;
import org.whispersystems.textsecuregcm.securevaluerecovery.SecureValueRecoveryClient;
import org.whispersystems.textsecuregcm.storage.AccountLockManager;
import org.whispersystems.textsecuregcm.storage.AccountStore;
import org.whispersystems.textsecuregcm.storage.Accounts;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.ChangeNumberWaitingPeriodManager;
import org.whispersystems.textsecuregcm.storage.ChangeNumberWaitingPeriodStore;
import org.whispersystems.textsecuregcm.storage.ChangeNumberWaitingPeriods;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.DynamoProfileDataStore;
import org.whispersystems.textsecuregcm.storage.FoundationDbVersion;
import org.whispersystems.textsecuregcm.storage.IssuedReceiptsManager;
import org.whispersystems.textsecuregcm.storage.KeysManager;
import org.whispersystems.textsecuregcm.storage.MessagesCache;
import org.whispersystems.textsecuregcm.storage.MessagesManager;
import org.whispersystems.textsecuregcm.storage.PagedSingleUseKEMPreKeyStore;
import org.whispersystems.textsecuregcm.storage.PersistentMessageStore;
import org.whispersystems.textsecuregcm.storage.PhoneNumberIdentifierStore;
import org.whispersystems.textsecuregcm.storage.PhoneNumberIdentifiers;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordStore;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswords;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.PostgresPersistence;
import org.whispersystems.textsecuregcm.storage.ProfileAvatarStore;
import org.whispersystems.textsecuregcm.storage.ProfileAvatars;
import org.whispersystems.textsecuregcm.storage.ProfileDataStore;
import org.whispersystems.textsecuregcm.storage.Profiles;
import org.whispersystems.textsecuregcm.storage.ProfilesManager;
import org.whispersystems.textsecuregcm.storage.ProfilesV2;
import org.whispersystems.textsecuregcm.storage.RedeemedReceiptsManager;
import org.whispersystems.textsecuregcm.storage.RepeatedUseECSignedPreKeyStore;
import org.whispersystems.textsecuregcm.storage.RepeatedUseKEMSignedPreKeyStore;
import org.whispersystems.textsecuregcm.storage.ReportMessageManager;
import org.whispersystems.textsecuregcm.storage.ReportMessageStore;
import org.whispersystems.textsecuregcm.storage.SingleUseECPreKeyStore;
import org.whispersystems.textsecuregcm.storage.SingleUseKEMPreKeyStorage;
import org.whispersystems.textsecuregcm.storage.SubscriptionManager;
import org.whispersystems.textsecuregcm.storage.Subscriptions;
import org.whispersystems.textsecuregcm.storage.foundationdb.FaultTolerantDatabase;
import org.whispersystems.textsecuregcm.storage.foundationdb.FoundationDbMessageStore;
import org.whispersystems.textsecuregcm.storage.foundationdb.VersionstampUUIDCipher;
import org.whispersystems.textsecuregcm.subscriptions.AppleAppStoreClient;
import org.whispersystems.textsecuregcm.subscriptions.AppleAppStoreManager;
import org.whispersystems.textsecuregcm.subscriptions.GooglePlayBillingManager;
import org.whispersystems.textsecuregcm.util.FeatureUnavailableException;
import org.whispersystems.textsecuregcm.util.ManagedAwsCrt;
import org.whispersystems.textsecuregcm.util.ManagedExecutors;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.s3.S3AsyncClient;

/**
 * Construct utilities commonly used by worker commands
 */
public record CommandDependencies(
    AccountsManager accountsManager,
    ProfilesManager profilesManager,
    ReportMessageManager reportMessageManager,
    MessagesCache messagesCache,
    MessagesManager messagesManager,
    KeysManager keysManager,
    PhoneNumberRecoveryPasswordsManager phoneNumberRecoveryPasswordsManager,
    PushNotificationSender apnSender,
    PushNotificationSender fcmSender,
    PushNotificationManager pushNotificationManager,
    PushNotificationExperimentSamples pushNotificationExperimentSamples,
    FaultTolerantRedisClusterClient cacheCluster,
    FaultTolerantRedisClusterClient pushSchedulerCluster,
    ClientResources.Builder redisClusterClientResourcesBuilder,
    BackupManager backupManager,
    IssuedReceiptsManager issuedReceiptsManager,
    GooglePlayBillingManager googlePlayBillingManager,
    AppleAppStoreManager appleAppStoreManager,
    SubscriptionManager subscriptionManager,
    DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager,
    DynamoDbAsyncClient dynamoDbAsyncClient,
    DynamoDbClient dynamoDbClient,
    PhoneNumberIdentifierStore phoneNumberIdentifiers,
    FDB fdb,
    AccountLockManager accountLockManager) {

  static CommandDependencies build(
      final String name,
      final Environment environment,
      final WhisperServerConfiguration configuration)
      throws IOException, GeneralSecurityException, InvalidInputException {
    configuration.getRuntimeMode().requireWorker(name);
    configuration.validateRuntimeConfiguration();
    if (name.equals("scheduled-apn-sender") && configuration.enabledPushTypes().isEmpty()) {
      throw new FeatureUnavailableException("Push notification worker");
    }
    final boolean gcpPilot = configuration.isGcpPilot();
    Clock clock = Clock.systemUTC();

    MetricsUtil.configureLogging(configuration, environment);

    environment.getObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    final FDB fdb;
    final Map<Integer, List<FaultTolerantDatabase>> messageDatabasesByEpoch;
    if (configuration.getPostgresConfiguration() == null) {
      fdb = FDB.selectAPIVersion(FoundationDbVersion.getFoundationDbApiVersion());

      // Jetty and the FoundationDB client both register shutdown hooks to begin shutdown/cleanup operations. There isn't
      // a good way to coordinate or enforce ordering between shutdown hooks, and so the two processes will race.
      // Generally, FoundationDB will shut down before Jetty does, meaning we'll still be trying to serve requests that
      // require talking to FoundationDB even though FoundationDB has shut down. To avoid that scenario, we disabled
      // FoundationDB's shutdown hook and let the JVM terminate its (daemon) threads at exit. This isn't as graceful as
      // we'd like, but is the least bad option given current constraints.
      fdb.disableShutdownHook();

      final FoundationDbExternalClientConfiguration externalClientConfiguration = configuration.getFoundationDbMessagesConfiguration()
          .externalClientConfiguration();
      if (externalClientConfiguration != null) {
        // If threadsPerClient is not specified, we default to the cluster size so that there is 1:1 correspondence between
        // Database objects and threads.
        final int clientThreadsPerVersion = externalClientConfiguration.threadsPerClient()
            .orElseGet(() -> configuration.getFoundationDbMessagesConfiguration().clusters().size());
        externalClientConfiguration.clientLibraryPaths().forEach(path -> fdb.options().setExternalClientLibrary(path));
        fdb.options().setClientThreadsPerVersion(clientThreadsPerVersion);
      }

      {
        final Map<String, FaultTolerantDatabase> faultTolerantDatabasesByName =
            configuration.getFoundationDbMessagesConfiguration().clusters().entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey,
                    entry -> {
                      try {
                        final Database database = entry.getValue().build(fdb);
                        database.options().setMaxWatches(configuration.getFoundationDbMessagesConfiguration().maxWatchesPerClient());
                        database.options().setTransactionTimeout(
                            configuration.getFoundationDbMessagesConfiguration().transactionTimeout().toMillis());
                        database.options().setTransactionRetryLimit(
                            configuration.getFoundationDbMessagesConfiguration().transactionRetryLimit());

                        return new FaultTolerantDatabase(database, entry.getKey(),
                            configuration.getFoundationDbMessagesConfiguration().circuitBreakerConfigurationName());
                      } catch (final IOException e) {
                        throw new UncheckedIOException("Failed to construct FoundationDB database", e);
                      }
                    }));

        messageDatabasesByEpoch = configuration.getFoundationDbMessagesConfiguration().epochs().entrySet().stream()
            .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey,
                entry -> entry.getValue().stream()
                    .map(faultTolerantDatabasesByName::get)
                    .toList()));
      }

    } else {
      fdb = null;
      messageDatabasesByEpoch = Map.of();
    }

    final AwsCredentialsProvider awsCredentialsProvider = gcpPilot ? null : configuration.getAwsCredentialsConfiguration().build();

    ScheduledExecutorService dynamicConfigurationExecutor = ScheduledExecutorServiceBuilder.of(environment, "dynamicConfiguration")
        .threads(1).build();

    DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager =
        new DynamicConfigurationManager<>(
            configuration.getDynamicConfig().build(dynamicConfigurationExecutor), DynamicConfiguration.class);
    dynamicConfigurationManager.start();
    ExperimentEnrollmentManager experimentEnrollmentManager =
        new ExperimentEnrollmentManager(dynamicConfigurationManager);

    final ClientResources.Builder redisClientResourcesBuilder = ClientResources.builder();

    FaultTolerantRedisClusterClient cacheCluster = configuration.getCacheClusterConfiguration()
        .build("main_cache", redisClientResourcesBuilder);
    FaultTolerantRedisClusterClient pushSchedulerCluster = configuration.getPushSchedulerCluster()
        .build("push_scheduler", redisClientResourcesBuilder);
    PubSubRedisClient pubsubClient =
        configuration.getRedisPubSubConfiguration().build("pubsub", redisClientResourcesBuilder.build());

    Scheduler messageDeliveryScheduler = Schedulers.fromExecutorService(
        environment.lifecycle().executorService("messageDelivery").minThreads(4).maxThreads(4).build());
    ExecutorService messageDeletionExecutor = ExecutorServiceBuilder.of(environment, "messageDeletion")
        .minThreads(4).maxThreads(4).build();
    ExecutorService secureValueRecoveryServiceExecutor = ExecutorServiceBuilder.of(environment, "secureValueRecoveryService")
        .maxThreads(8).minThreads(8).build();
    ExecutorService storageServiceExecutor = ExecutorServiceBuilder.of(environment, "storageService")
        .maxThreads(8).minThreads(8).build();
    ExecutorService remoteStorageHttpExecutor = ExecutorServiceBuilder.of(environment, "remoteStorage")

        .minThreads(0).maxThreads(Integer.MAX_VALUE).workQueue(new SynchronousQueue<>())
        .keepAliveTime(io.dropwizard.util.Duration.seconds(60L)).build();
    ExecutorService apnSenderExecutor = ExecutorServiceBuilder.of(environment, "apnSender")
        .maxThreads(1).minThreads(1).build();
    ExecutorService fcmSenderExecutor = ExecutorServiceBuilder.of(environment, "fcmSender")
        .maxThreads(16).minThreads(16).build();
    ExecutorService clientEventExecutor = ManagedExecutors.newVirtualThreadPerTaskExecutor(
      "clientEvent", configuration.getVirtualThreadConfiguration().maxConcurrentThreadsPerExecutor(), environment);
    ExecutorService asyncOperationQueueingExecutor = ExecutorServiceBuilder.of(environment, "asyncOperationQueueing")
        .minThreads(1).maxThreads(1).build();
    ExecutorService disconnectionRequestListenerExecutor = ManagedExecutors.newVirtualThreadPerTaskExecutor(
        "disconnectionRequest",
        configuration.getVirtualThreadConfiguration().maxConcurrentThreadsPerExecutor(),
        environment);

    final ScheduledExecutorService messagePollExecutor = ScheduledExecutorServiceBuilder.of(environment, "messagePollExecutor")
      .threads(1).build();
    final ScheduledExecutorService retryExecutor = ScheduledExecutorServiceBuilder.of(environment, "retry")
      .threads(1).build();
    final ScheduledExecutorService presenceRenewalExecutor =
        ScheduledExecutorServiceBuilder.of(environment, "presenceRenewal").threads(1).build();

    ExternalServiceCredentialsGenerator storageCredentialsGenerator = configuration.isStorageEnabled() ? SecureStorageController.credentialsGenerator(
        configuration.getSecureStorageServiceConfiguration()) : null;
    ExternalServiceCredentialsGenerator secureValueRecovery2CredentialsGenerator = configuration.isSvr2Enabled() ? SecureValueRecovery2Controller.credentialsGenerator(
        configuration.getSvr2Configuration()) : null;
    ExternalServiceCredentialsGenerator secureValueRecoveryBCredentialsGenerator =
        gcpPilot ? null : SecureValueRecoveryBCredentialsGeneratorFactory.svrbCredentialsGenerator(configuration.getSvrbConfiguration());

    final ExecutorService awsSdkMetricsExecutor = gcpPilot ? null : ManagedExecutors.newVirtualThreadPerTaskExecutor(
        "awsSdkMetrics",
        configuration.getVirtualThreadConfiguration().maxConcurrentThreadsPerExecutor(),
        environment);

    DynamoDbAsyncClient dynamoDbAsyncClient = gcpPilot ? null : configuration.getDynamoDbClientConfiguration()
        .buildAsyncClient(awsCredentialsProvider, new MicrometerAwsSdkMetricPublisher(awsSdkMetricsExecutor, "dynamoDbAsyncCommand"));

    DynamoDbClient dynamoDbClient = gcpPilot ? null : configuration.getDynamoDbClientConfiguration()
        .buildSyncClient(awsCredentialsProvider, new MicrometerAwsSdkMetricPublisher(awsSdkMetricsExecutor, "dynamoDbSyncCommand"));

    final AwsCredentialsProvider cdnCredentialsProvider = gcpPilot ? null : configuration.getCdnConfiguration().credentials().build();
    final S3AsyncClient asyncCdnS3Client = gcpPilot ? null : S3AsyncClient.builder()
        .credentialsProvider(cdnCredentialsProvider)
        .region(Region.of(configuration.getCdnConfiguration().region()))
        .build();


    final PostgresPersistence postgres = PostgresPersistence.build(environment, configuration.getPostgresConfiguration(),
            configuration.getMessageRetention(), RemoveExpiredAccountsCommand.MAX_IDLE_DURATION, configuration.getRecoveryRetention(), configuration.getReportMessageConfiguration().getReportTtl(), clock, messageDeletionExecutor);
    PhoneNumberRecoveryPasswordStore phoneNumberRecoveryPasswords = postgres != null ? postgres.recoveryPasswords() : new PhoneNumberRecoveryPasswords(
        configuration.getDynamoDbTables().getRegistrationRecovery().getTableName(),
        configuration.getRecoveryRetention(),
        dynamoDbClient,
        clock);

    RedeemedReceiptsManager redeemedReceiptsManager = gcpPilot ? null : new RedeemedReceiptsManager(clock,
        configuration.getDynamoDbTables().getRedeemedReceipts().getTableName(),
        dynamoDbClient);

    AccountStore accounts = postgres != null ? postgres.accounts() : new Accounts(
        clock,
        dynamoDbClient,
        dynamoDbAsyncClient,
        redeemedReceiptsManager,
        configuration.getDynamoDbTables().getAccounts().getTableName(),
        configuration.getDynamoDbTables().getAccounts().getPhoneNumberTableName(),
        configuration.getDynamoDbTables().getAccounts().getPhoneNumberIdentifierTableName(),
        configuration.getDynamoDbTables().getAccounts().getUsernamesTableName(),
        configuration.getDynamoDbTables().getDeletedAccounts().getTableName(),
        configuration.getDynamoDbTables().getAccounts().getUsedLinkDeviceTokensTableName());

    PhoneNumberIdentifierStore phoneNumberIdentifiers = postgres != null ? postgres.phoneNumbers() : new PhoneNumberIdentifiers(dynamoDbAsyncClient,
        configuration.getDynamoDbTables().getPhoneNumberIdentifiers().getTableName());

    ProfileDataStore profileStore = postgres != null ? postgres.profiles() : new DynamoProfileDataStore(
        new Profiles(dynamoDbClient, dynamoDbAsyncClient, configuration.getDynamoDbTables().getProfilesV1().getTableName()),
        new ProfilesV2(dynamoDbClient, dynamoDbAsyncClient, configuration.getDynamoDbTables().getProfilesV2().getTableName()));
    ProfileAvatarStore profileAvatars = postgres != null ? postgres.profileAvatars() : new ProfileAvatars(dynamoDbClient,
        configuration.getDynamoDbTables().getProfileAvatars().getTableName(), RemoveExpiredAccountsCommand.MAX_IDLE_DURATION, clock);

    S3AsyncClient asyncKeysS3Client = postgres != null ? null : S3AsyncClient.builder()
        .credentialsProvider(awsCredentialsProvider)
        .region(Region.of(configuration.getPagedSingleUseKEMPreKeyStore().region()))
        .build();
    SingleUseKEMPreKeyStorage pagedSingleUseKEMPreKeyStore = postgres != null ? postgres.kemPreKeys() : new PagedSingleUseKEMPreKeyStore(
        dynamoDbAsyncClient, asyncKeysS3Client,
        configuration.getDynamoDbTables().getPagedKemKeys().getTableName(),
        configuration.getPagedSingleUseKEMPreKeyStore().bucket());

    KeysManager keys = new KeysManager(
        postgres != null ? postgres.ecPreKeys()
            : new SingleUseECPreKeyStore(dynamoDbAsyncClient, configuration.getDynamoDbTables().getEcKeys().getTableName()),
        pagedSingleUseKEMPreKeyStore,
        postgres != null ? postgres.signedEcKeys() : new RepeatedUseECSignedPreKeyStore(dynamoDbAsyncClient,
            configuration.getDynamoDbTables().getEcSignedPreKeys().getTableName()),
        postgres != null ? postgres.signedKemKeys() : new RepeatedUseKEMSignedPreKeyStore(dynamoDbAsyncClient,
            configuration.getDynamoDbTables().getKemLastResortKeys().getTableName()));
    PersistentMessageStore messageStore = postgres.messages();
    FaultTolerantRedisClusterClient messagesCluster = configuration.getMessageCacheConfiguration()
        .getRedisClusterConfiguration().build("messages", redisClientResourcesBuilder);
    FaultTolerantRedisClusterClient rateLimitersCluster = configuration.getRateLimitersCluster().build("rate_limiters",
        redisClientResourcesBuilder);
    SecureValueRecoveryClient secureValueRecovery2Client = !configuration.isSvr2Enabled() ? null : new SecureValueRecoveryClient(
        secureValueRecovery2CredentialsGenerator,
        secureValueRecoveryServiceExecutor,
        retryExecutor,
        configuration.getSvr2Configuration(),
        () -> dynamicConfigurationManager.getConfiguration().getSvr2StatusCodesToIgnoreForAccountDeletion());
    SecureValueRecoveryClient secureValueRecoveryBClient = gcpPilot ? null : new SecureValueRecoveryClient(
        secureValueRecoveryBCredentialsGenerator,
        secureValueRecoveryServiceExecutor,
        retryExecutor,
        configuration.getSvrbConfiguration(),
        () -> dynamicConfigurationManager.getConfiguration().getSvrbStatusCodesToIgnoreForAccountDeletion());
    SecureStorageClient secureStorageClient = !configuration.isStorageEnabled() ? null : new SecureStorageClient(storageCredentialsGenerator,
        storageServiceExecutor, retryExecutor, configuration.getSecureStorageServiceConfiguration());
    DisconnectionRequestManager disconnectionRequestManager = new DisconnectionRequestManager(pubsubClient,
        disconnectionRequestListenerExecutor, retryExecutor);
    MessagesCache messagesCache = new MessagesCache(messagesCluster,
        messageDeliveryScheduler, messageDeletionExecutor, retryExecutor, Clock.systemUTC());
    final FoundationDbMessageStore foundationDbMessageStore = postgres != null ? null : new FoundationDbMessageStore(messageDatabasesByEpoch,
        configuration.getFoundationDbMessagesConfiguration().activeEpoch(),
        new VersionstampUUIDCipher(configuration.getFoundationDbMessagesConfiguration().currentVersionstampCipherKey(),
            configuration.getFoundationDbMessagesConfiguration().versionstampCipherKeys().get(configuration.getFoundationDbMessagesConfiguration().currentVersionstampCipherKey()).value()),
        presenceRenewalExecutor,
        Clock.systemUTC(),
        configuration.getFoundationDbMessagesConfiguration().batchPriorityTransactionTimeout(),
        configuration.getFoundationDbMessagesConfiguration().batchPriorityTransactionRetryLimit());
    final org.whispersystems.textsecuregcm.avatars.GcsAvatarStorage gcsAvatars = gcpPilot
        ? configuration.getGcpAvatars().build(messageDeletionExecutor, clock) : null;
    if (gcsAvatars != null) environment.lifecycle().manage(new io.dropwizard.lifecycle.Managed() {
      @Override public void stop() throws Exception { gcsAvatars.close(); }
    });
    ProfilesManager profilesManager = gcpPilot
        ? new ProfilesManager(profileStore, profileAvatars, cacheCluster, retryExecutor, gcsAvatars)
        : new ProfilesManager(profileStore, profileAvatars, cacheCluster, retryExecutor, asyncCdnS3Client,
            configuration.getCdnConfiguration().bucket());
    ReportMessageStore reportMessageStore = postgres.reportMessages();
    ReportMessageManager reportMessageManager = new ReportMessageManager(reportMessageStore, rateLimitersCluster,
        configuration.getReportMessageConfiguration().getCounterTtl());
    RedisMessageAvailabilityManager redisMessageAvailabilityManager =
        new RedisMessageAvailabilityManager(messagesCluster, clientEventExecutor, asyncOperationQueueingExecutor);
    final MessagesManager messagesManager =
        new MessagesManager(messageStore, messagesCache, foundationDbMessageStore, redisMessageAvailabilityManager,
            reportMessageManager, messageDeletionExecutor, Clock.systemUTC(), experimentEnrollmentManager);
    AccountLockManager accountLockManager = postgres != null ? postgres.accountLocks() : new AccountLockManager(dynamoDbClient,
        configuration.getDynamoDbTables().getDeletedAccountsLock().getTableName());
    PhoneNumberRecoveryPasswordsManager phoneNumberRecoveryPasswordsManager =
        new PhoneNumberRecoveryPasswordsManager(phoneNumberRecoveryPasswords);
    final ChangeNumberWaitingPeriodStore changeNumberWaitingPeriods = postgres != null ? postgres.waitingPeriods() : new ChangeNumberWaitingPeriods(
        configuration.getDynamoDbTables().getChangeNumberWaitingPeriods().getTableName(), dynamoDbClient);
    final ChangeNumberWaitingPeriodManager changeNumberWaitingPeriodManager = new ChangeNumberWaitingPeriodManager(
        changeNumberWaitingPeriods, configuration.getChangeNumber().postRegistrationWaitingPeriod(), clock);
    final WebAuthnCeremonyManager webAuthnCeremonyManager = new WebAuthnCeremonyManager(
        configuration.getRegistrationWebAuthnConfiguration().relyingPartyId(),
        configuration.getRegistrationWebAuthnConfiguration().origin(),
        configuration.getRegistrationWebAuthnConfiguration().challengeTtl(),
        configuration.getRegistrationWebAuthnConfiguration().userHandleBlindingSecret().value(),
        rateLimitersCluster);
    AccountsManager accountsManager = new AccountsManager(accounts, phoneNumberIdentifiers, cacheCluster,
        pubsubClient, accountLockManager, keys, messagesManager, profilesManager,
        changeNumberWaitingPeriodManager, secureStorageClient, secureValueRecovery2Client, disconnectionRequestManager,
        phoneNumberRecoveryPasswordsManager, messagePollExecutor,
        retryExecutor, clock, configuration.getLinkDeviceSecretConfiguration().secret().value(),
        configuration.getRegistrationTotpConfiguration().maxValidationDelay(),
        webAuthnCeremonyManager);
    RateLimiters rateLimiters = RateLimiters.create(dynamicConfigurationManager, rateLimitersCluster, retryExecutor);
    final BackupsDb backupsDb =
        gcpPilot ? null : new BackupsDb(dynamoDbAsyncClient, configuration.getDynamoDbTables().getBackups().getTableName(), clock);
    final GenericServerSecretParams backupsGenericZkSecretParams;
    try {
      backupsGenericZkSecretParams =
          new GenericServerSecretParams(configuration.getChatZkConfig().serverSecret().value());
    } catch (InvalidInputException e) {
      throw new IllegalArgumentException(e);
    }
    final BackupManager backupManager = gcpPilot ? null : new BackupManager(
        backupsDb,
        backupsGenericZkSecretParams,
        rateLimiters,
        new TusAttachmentGenerator(configuration.getTus()),
        new Cdn3BackupCredentialGenerator(configuration.getTus()),
        new Cdn3RemoteStorageManager(
            remoteStorageHttpExecutor,
            retryExecutor,
            configuration.getCdn3StorageManagerConfiguration()),
        secureValueRecoveryBCredentialsGenerator,
        secureValueRecoveryBClient,
        clock,
        configuration.getBackupConfiguration());

    final IssuedReceiptsManager issuedReceiptsManager = gcpPilot ? null : new IssuedReceiptsManager(
        configuration.getDynamoDbTables().getIssuedReceipts().getTableName(),
        dynamoDbClient,
        configuration.getDynamoDbTables().getIssuedReceipts().getGenerator(),
        configuration.getDynamoDbTables().getIssuedReceipts().getMaxReceiptsPerSubscriptionPayment());

    final ServerSecretParams zkSecretParams = new ServerSecretParams(configuration.getGroupsZkConfig().serverSecret().value());
    final ServerZkReceiptOperations zkReceiptOperations = new ServerZkReceiptOperations(zkSecretParams);
    GooglePlayBillingManager googlePlayBillingManager = gcpPilot ? null : new GooglePlayBillingManager(
        new ByteArrayInputStream(configuration.getGooglePlayBilling().credentialsJson().getBytes(StandardCharsets.UTF_8)),
        configuration.getGooglePlayBilling().packageName(),
        configuration.getGooglePlayBilling().applicationName(),
        configuration.getGooglePlayBilling().productIdToLevel());
    AppleAppStoreManager appleAppStoreManager = gcpPilot ? null : new AppleAppStoreManager(
        new AppleAppStoreClient(
            configuration.getAppleAppStore().env(),
            configuration.getAppleAppStore().bundleId(),
            configuration.getAppleAppStore().appAppleId(),
            configuration.getAppleAppStore().issuerId(),
            configuration.getAppleAppStore().keyId(),
            configuration.getAppleAppStore().encodedKey().value(),
            configuration.getAppleAppStore().appleRootCerts(),
            configuration.getAppleAppStore().retryConfigurationName()),
        configuration.getAppleAppStore().subscriptionGroupId(),
        configuration.getAppleAppStore().productIdToLevel());
    final SubscriptionManager subscriptionManager = gcpPilot ? null : new SubscriptionManager(
        new Subscriptions(configuration.getDynamoDbTables().getSubscriptions().getTableName(), dynamoDbClient),
        List.of(googlePlayBillingManager, appleAppStoreManager),
        zkReceiptOperations,
        issuedReceiptsManager);

    PushNotificationSender apnSender = configuration.isApnsEnabled()
        ? new APNSender(apnSenderExecutor, Clock.systemUTC(), configuration.getApnConfiguration())
        : PushNotificationSender.unavailable("APNs");
    PushNotificationSender fcmSender = configuration.isFcmEnabled()
        ? new FcmSender(fcmSenderExecutor, configuration.getFcmConfiguration().credentials().value())
        : PushNotificationSender.unavailable("FCM");
    PushNotificationScheduler pushNotificationScheduler = new PushNotificationScheduler(pushSchedulerCluster,
        apnSender, fcmSender, accountsManager, 0, 0, retryExecutor);
    PushNotificationManager pushNotificationManager = new PushNotificationManager(accountsManager,
        apnSender, fcmSender, pushNotificationScheduler);
    PushNotificationExperimentSamples pushNotificationExperimentSamples =
        gcpPilot ? null : new PushNotificationExperimentSamples(dynamoDbAsyncClient,
            configuration.getDynamoDbTables().getPushNotificationExperimentSamples().getTableName(),
            Clock.systemUTC());

    if (apnSender instanceof io.dropwizard.lifecycle.Managed managedApns) environment.lifecycle().manage(managedApns);
    environment.lifecycle().manage(disconnectionRequestManager);
    environment.lifecycle().manage(redisMessageAvailabilityManager);
    if (!gcpPilot) environment.lifecycle().manage(new ManagedAwsCrt());

    return new CommandDependencies(
        accountsManager,
        profilesManager,
        reportMessageManager,
        messagesCache,
        messagesManager,
        keys,
        phoneNumberRecoveryPasswordsManager,
        apnSender,
        fcmSender,
        pushNotificationManager,
        pushNotificationExperimentSamples,
        cacheCluster,
        pushSchedulerCluster,
        redisClientResourcesBuilder,
        backupManager,
        issuedReceiptsManager,
        googlePlayBillingManager,
        appleAppStoreManager,
        subscriptionManager,
        dynamicConfigurationManager,
        dynamoDbAsyncClient,
        dynamoDbClient,
        phoneNumberIdentifiers,
        fdb,
        accountLockManager);
  }

}
