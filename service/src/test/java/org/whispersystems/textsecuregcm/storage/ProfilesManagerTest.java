/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import io.lettuce.core.RedisException;
import io.lettuce.core.cluster.api.async.RedisAdvancedClusterAsyncCommands;
import io.lettuce.core.cluster.api.sync.RedisAdvancedClusterCommands;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.whispersystems.textsecuregcm.avatars.AvatarObjectStorage;
import org.whispersystems.textsecuregcm.redis.ClusterLuaScript;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.tests.util.MockRedisFuture;
import org.whispersystems.textsecuregcm.tests.util.ProfileTestHelper;
import org.whispersystems.textsecuregcm.tests.util.RedisClusterHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;

@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class ProfilesManagerTest {

  private ProfileDataStore profiles;
  private ProfileAvatarStore profileAvatars;
  private RedisAdvancedClusterCommands<byte[], byte[]> commands;
  private RedisAdvancedClusterAsyncCommands<byte[], byte[]> asyncCommands;
  private AvatarObjectStorage avatarStorage;
  private ClusterLuaScript setLuaScript;

  private ProfilesManager profilesManager;

  @BeforeEach
  void setUp() throws Exception {
    //noinspection unchecked
    commands = mock(RedisAdvancedClusterCommands.class);
    //noinspection unchecked
    asyncCommands = mock(RedisAdvancedClusterAsyncCommands.class);
    final FaultTolerantRedisClusterClient cacheCluster = RedisClusterHelper.builder()
        .binaryCommands(commands)
        .binaryAsyncCommands(asyncCommands)
        .build();

    profiles = mock(ProfileDataStore.class);
    profileAvatars = mock(ProfileAvatarStore.class);
    avatarStorage = mock(AvatarObjectStorage.class);
    when(avatarStorage.delete(anyString())).thenReturn(CompletableFuture.completedFuture(null));
    when(avatarStorage.refresh(anyString())).thenReturn(CompletableFuture.completedFuture(true));
    setLuaScript = mock(ClusterLuaScript.class);

    profilesManager = new ProfilesManager(profiles, profileAvatars, cacheCluster, mock(ScheduledExecutorService.class),
        avatarStorage, setLuaScript);
  }

  @Test
  public void testGetV1ProfileInCache() throws InvalidInputException {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);
    final byte[] name = TestRandomUtil.nextBytes(81);
    final byte[] commitment = new ProfileKey(new byte[32]).getCommitment(new ServiceId.Aci(uuid)).serialize();
    when(commands.hget(eq(ProfilesManager.getCacheKeyV1(uuid)), eq(versionHex.getBytes())))
        .thenReturn(String.format(
            "{\"version\": \"%s\", \"name\": \"%s\", \"avatar\": \"someavatar\", \"commitment\":\"%s\"}",
            versionHex,
            ProfileTestHelper.encodeToBase64(name),
            ProfileTestHelper.encodeToBase64(commitment)).getBytes());

    Optional<VersionedProfileV1> profile = profilesManager.getV1(uuid, versionHex);

    assertTrue(profile.isPresent());
    assertArrayEquals(profile.get().name(), name);
    assertEquals("someavatar", profile.get().avatar());
    assertArrayEquals(profile.get().commitment(), commitment);

    verify(commands, times(1)).hget(eq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(versionHex.getBytes()));
    verifyNoMoreInteractions(commands);
    verifyNoMoreInteractions(profiles);
  }

  @Test
  public void testGetV1ProfileNotInCache() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);
    final byte[] name = TestRandomUtil.nextBytes(81);
    final VersionedProfileV1 profile = new VersionedProfileV1(versionHex, name, "someavatar", null, null,
        null, null, "somecommitment".getBytes());

    when(commands.hget(eq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(versionHex.getBytes()))).thenReturn(null);
    when(profiles.getV1(eq(uuid), eq(versionHex))).thenReturn(Optional.of(profile));

    Optional<VersionedProfileV1> retrieved = profilesManager.getV1(uuid, versionHex);

    assertTrue(retrieved.isPresent());
    assertEquals(retrieved.get(), profile);

    final byte[] v1ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profile);

    verify(commands, times(1)).hget(eq(ProfilesManager.getCacheKeyV1(uuid)), eq(versionHex.getBytes()));
    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            Arrays.equals(args.get(0), versionHex.getBytes())
                && Arrays.equals(args.get(1), v1ProfileBytes)
                && args.get(2).length == 0));

    verify(commands, times(1)).hget(aryEq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(versionHex.getBytes()));
    verifyNoMoreInteractions(commands);
    verifyNoMoreInteractions(setLuaScript);

    verify(profiles, times(1)).getV1(eq(uuid), eq(versionHex));
    verifyNoMoreInteractions(profiles);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void testGetV1ProfileBrokenCache(final boolean failUpdateCache) {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);
    final byte[] name = TestRandomUtil.nextBytes(81);
    final VersionedProfileV1 profile = new VersionedProfileV1(versionHex, name, "someavatar", null, null,
        null, null, "somecommitment".getBytes());

    when(commands.hget(eq(ProfilesManager.getCacheKeyV1(uuid)), eq(versionHex.getBytes()))).thenThrow(new RedisException("Connection lost"));
    if (failUpdateCache) {
      when(commands.hset(eq(ProfilesManager.getCacheKeyV1(uuid)), eq(versionHex.getBytes()), any(byte[].class)))
        .thenThrow(new RedisException("Connection lost"));
    }
    when(profiles.getV1(eq(uuid), eq(versionHex))).thenReturn(Optional.of(profile));

    Optional<VersionedProfileV1> retrieved = profilesManager.getV1(uuid, versionHex);

    assertTrue(retrieved.isPresent());
    assertEquals(retrieved.get(), profile);

    verify(commands, times(1)).hget(eq(ProfilesManager.getCacheKeyV1(uuid)), eq(versionHex.getBytes()));
    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            Arrays.equals(args.get(0), versionHex.getBytes())
                && args.get(1).length > 0
                && args.get(2).length == 0));
    verifyNoMoreInteractions(commands);
    verifyNoMoreInteractions(setLuaScript);

    verify(profiles, times(1)).getV1(eq(uuid), eq(versionHex));
    verifyNoMoreInteractions(profiles);
  }

  @Test
  public void testSetV1() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);
    final byte[] name = TestRandomUtil.nextBytes(81);
    final VersionedProfileV1 profile = new VersionedProfileV1(versionHex, name, "someavatar", null, null,
        null, null, "somecommitment".getBytes());

    profilesManager.setV1(uuid, profile);

    final byte[] v1ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profile);

    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            Arrays.equals(args.get(0), versionHex.getBytes())
                && Arrays.equals(args.get(1), v1ProfileBytes)
                && args.get(2).length == 0
                && args.get(3).length == 0));
    verifyNoMoreInteractions(setLuaScript);

    verify(profiles, times(1)).setV1(eq(uuid), eq(profile));
    verify(profiles).deleteV2(uuid);
    verifyNoMoreInteractions(profiles);
    verify(commands).del(aryEq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(ProfilesManager.getCacheKeyV2(uuid)));
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void testDeleteAll(final boolean includeAvatar) {
    final UUID uuid = UUID.randomUUID();

    final String avatarOne = "avatar1";
    final String avatarTwo = "avatar2";
    when(profiles.deleteV1(uuid)).thenReturn(CompletableFuture.completedFuture(List.of(avatarOne, avatarTwo)));
    when(profiles.deleteV2(uuid)).thenReturn(CompletableFuture.completedFuture(null));
    when(asyncCommands.del(ProfilesManager.getCacheKeyV1(uuid), ProfilesManager.getCacheKeyV2(uuid))).thenReturn(MockRedisFuture.completedFuture(null));
    when(avatarStorage.delete(anyString()))
        .thenReturn(CompletableFuture.completedFuture(null))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("some error")));

    profilesManager.deleteAll(uuid, includeAvatar).join();

    verify(profiles).deleteV1(uuid);
    verify(profiles).deleteV2(uuid);
    verify(asyncCommands).del(ProfilesManager.getCacheKeyV1(uuid), ProfilesManager.getCacheKeyV2(uuid));
    if (includeAvatar) {
      verify(avatarStorage).delete(avatarOne);
      verify(avatarStorage).delete(avatarTwo);
    } else {
      verifyNoInteractions(avatarStorage);
    }
  }

  @Test
  public void testGetProfileInCache() {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final byte[] data = TestRandomUtil.nextBytes(128);
    final byte[] dataHash = TestRandomUtil.nextBytes(32);
    final byte[] commitment = TestRandomUtil.nextBytes(32);
    final byte[] paymentAddress = TestRandomUtil.nextBytes(64);
    final byte[] paymentAddressHash = TestRandomUtil.nextBytes(32);

    when(commands.hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version))).thenReturn(String.format(
        """
            {
              "version":"%s",
              "data":"%s",
              "dataHash":"%s",
              "paymentAddress":"%s",
              "paymentAddressHash":"%s",
              "commitment":"%s"
            }
        """,
        ProfileTestHelper.encodeToBase64(version),
        ProfileTestHelper.encodeToBase64(data),
        ProfileTestHelper.encodeToBase64(dataHash),
        ProfileTestHelper.encodeToBase64(paymentAddress),
        ProfileTestHelper.encodeToBase64(paymentAddressHash),
        ProfileTestHelper.encodeToBase64(commitment)).getBytes());

    Optional<VersionedProfile> profile = profilesManager.get(uuid, version);

    assertTrue(profile.isPresent());
    assertArrayEquals(profile.get().data(), data);
    assertArrayEquals(profile.get().dataHash(), dataHash);
    assertArrayEquals(profile.get().commitment(), commitment);
    assertArrayEquals(profile.get().paymentAddress(), paymentAddress);
    assertArrayEquals(profile.get().paymentAddressHash(), paymentAddressHash);

    verify(commands, times(1)).hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version));
    verifyNoMoreInteractions(commands);
    verifyNoMoreInteractions(profiles);
  }

  @Test
  public void testGetProfileNotInCache() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final VersionedProfile profile = new VersionedProfile(version, TestRandomUtil.nextBytes(128),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(64),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(32));

    when(commands.hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version))).thenReturn(null);
    when(profiles.getV2(eq(uuid), aryEq(version))).thenReturn(Optional.of(profile));

    final Optional<VersionedProfile> retrieved = profilesManager.get(uuid, version);

    assertTrue(retrieved.isPresent());
    assertEquals(retrieved.get(), profile);

    final byte[] v2ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profile);

    verify(commands, times(1)).hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version));
    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            args.get(0).length == 0
                && args.get(1).length == 0
                && Arrays.equals(args.get(2), version)
                && Arrays.equals(args.get(3), v2ProfileBytes)));
    verifyNoMoreInteractions(commands);

    verify(profiles, times(1)).getV2(eq(uuid), aryEq(version));
    verifyNoMoreInteractions(profiles);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  public void testGetProfileBrokenCache(final boolean failUpdateCache) throws Exception {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final VersionedProfile profile = new VersionedProfile(version, TestRandomUtil.nextBytes(128),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(64),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(32));

    when(commands.hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version))).thenThrow(new RedisException("Connection lost"));
    if (failUpdateCache) {
      when(commands.hset(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version), any(byte[].class)))
          .thenThrow(new RedisException("Connection lost"));
    }
    when(profiles.getV2(eq(uuid), aryEq(version))).thenReturn(Optional.of(profile));

    final Optional<VersionedProfile> retrieved = profilesManager.get(uuid, version);

    assertTrue(retrieved.isPresent());
    assertEquals(retrieved.get(), profile);

    final byte[] v2ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profile);

    verify(commands, times(1)).hget(aryEq(ProfilesManager.getCacheKeyV2(uuid)), aryEq(version));
    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            args.get(0).length == 0
                && args.get(1).length == 0
                && Arrays.equals(args.get(2), version)
                && Arrays.equals(args.get(3), v2ProfileBytes)));    verifyNoMoreInteractions(commands);

    verify(profiles, times(1)).getV2(eq(uuid), aryEq(version));
    verifyNoMoreInteractions(profiles);
  }

  @Test
  public void testSet() throws Exception {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);

    final byte[] name = TestRandomUtil.nextBytes(81);
    final byte[] commitment = new ProfileKey(new byte[32]).getCommitment(new ServiceId.Aci(uuid)).serialize();
    final VersionedProfileV1 profileV1 = new VersionedProfileV1(versionHex, name, null, null, null, null, null, commitment);

    final byte[] expectedCurrentDataHash = TestRandomUtil.nextBytes(32);
    final VersionedProfile profileV2 = new VersionedProfile(version, TestRandomUtil.nextBytes(128),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(64),
        TestRandomUtil.nextBytes(32), commitment);

    profilesManager.set(uuid, profileV1, profileV2, expectedCurrentDataHash);

    final byte[] v1ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profileV1);
    final byte[] v2ProfileBytes = SystemMapper.jsonMapper().writeValueAsBytes(profileV2);

    verify(setLuaScript, times(1)).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))
                && Arrays.equals(keys.get(1), ProfilesManager.getCacheKeyV2(uuid))),
        argThat(args ->
            Arrays.equals(args.get(0), versionHex.getBytes())
                && Arrays.equals(args.get(1), v1ProfileBytes)
                && Arrays.equals(args.get(2), version)
                && Arrays.equals(args.get(3), v2ProfileBytes)));
    verify(commands).del(aryEq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(ProfilesManager.getCacheKeyV2(uuid)));
    verifyNoMoreInteractions(commands);
    verifyNoMoreInteractions(setLuaScript);

    verify(profiles).setBoth(eq(uuid), eq(profileV1), eq(profileV2), aryEq(expectedCurrentDataHash));
    verifyNoMoreInteractions(profiles);
  }

  @ParameterizedTest
  @MethodSource
  public void testSetExceptionCleansUpCache(final Class<? extends Exception> exceptionClass) throws WriteConflictException, InvalidInputException {
    final UUID uuid = UUID.randomUUID();
    final byte[] version = TestRandomUtil.nextBytes(32);
    final String versionHex = HexFormat.of().formatHex(version);

    final byte[] name = TestRandomUtil.nextBytes(81);
    final byte[] commitment = new ProfileKey(new byte[32]).getCommitment(new ServiceId.Aci(uuid)).serialize();
    final VersionedProfileV1 profileV1 = new VersionedProfileV1(versionHex, name, null, null, null, null, null, commitment);
    
    final byte[] wrongHash = TestRandomUtil.nextBytes(32);
    final VersionedProfile profileV2 = new VersionedProfile(version, TestRandomUtil.nextBytes(128),
        TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(64),
        TestRandomUtil.nextBytes(32), commitment);

    when(asyncCommands.del(ProfilesManager.getCacheKeyV1(uuid), ProfilesManager.getCacheKeyV2(uuid))).thenReturn(MockRedisFuture.completedFuture(null));

    doThrow(exceptionClass).when(profiles).setBoth(eq(uuid), eq(profileV1), eq(profileV2), aryEq(wrongHash));

    assertThrows(exceptionClass, () -> profilesManager.set(uuid, profileV1, profileV2, wrongHash));
    
    verify(commands).del(aryEq(ProfilesManager.getCacheKeyV1(uuid)), aryEq(ProfilesManager.getCacheKeyV2(uuid)));
  }
  
  static Collection<Arguments> testSetExceptionCleansUpCache() {
    return List.of(
        Arguments.of(WriteConflictException.class),
        Arguments.of(IllegalStateException.class)
    );
  }

  @Test
  void setAvatarForIdentity() {
    final byte[] identity = new byte[1];
    final String url1 = "url1";

    when(profileAvatars.setAvatarUrl(any(byte[].class), anyString()))
        .thenReturn(Optional.empty());

    profilesManager.setAvatarForIdentity(identity, url1);

    verify(profileAvatars).setAvatarUrl(identity, url1);
    verifyNoInteractions(avatarStorage);

    when(profileAvatars.setAvatarUrl(any(byte[].class), anyString()))
        .thenReturn(Optional.of(url1));

    final String url2 = "url2";
    profilesManager.setAvatarForIdentity(identity, url2);

    verify(profileAvatars).setAvatarUrl(identity, url2);
    verify(avatarStorage).delete(url1);
  }

  @Test
  void extendAvatarTtlForIdentity() {
    final String avatarPath = "somePath";
    when(profileAvatars.updateAvatarTtl(any(byte[].class))).thenReturn(Optional.of(avatarPath));

    assertEquals(Optional.of(avatarPath), profilesManager.extendAvatarTtlForIdentity(new byte[1]));

    verify(avatarStorage).refresh(avatarPath);
  }

  @Test
  void extendAvatarTtlForIdentityNotFound() {
    when(profileAvatars.updateAvatarTtl(any(byte[].class))).thenReturn(Optional.empty());

    assertTrue(profilesManager.extendAvatarTtlForIdentity(new byte[1]).isEmpty());

    verifyNoInteractions(avatarStorage);
  }

  @Test
  void extendAvatarTtlForIdentityMissingObject() {
    final String avatarPath = "somePath";
    when(profileAvatars.updateAvatarTtl(any(byte[].class))).thenReturn(Optional.of(avatarPath));

    when(avatarStorage.refresh(anyString()))
        .thenReturn(CompletableFuture.completedFuture(false));

    assertTrue(profilesManager.extendAvatarTtlForIdentity(new byte[1]).isEmpty());

    verify(avatarStorage).refresh(avatarPath);
    verify(profileAvatars).deleteAvatarUrl(any(byte[].class));
  }

  @Test
  void extendAvatarTtlForIdentityStorageRetry() {
    final String avatarPath = "somePath";
    when(profileAvatars.updateAvatarTtl(any(byte[].class))).thenReturn(Optional.of(avatarPath));

    when(avatarStorage.refresh(anyString()))
        .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("synthetic storage failure")))
        .thenReturn(CompletableFuture.completedFuture(true));

    assertEquals(Optional.of(avatarPath), profilesManager.extendAvatarTtlForIdentity(new byte[1]));

    verify(avatarStorage, times(2)).refresh(avatarPath);

    verify(profileAvatars, never()).deleteAvatarUrl(any(byte[].class));
  }

  @Test
  void deleteAvatarForIdentity() {
    final String avatarPath = "somePath";
    when(profileAvatars.deleteAvatarUrl(any(byte[].class))).thenReturn(Optional.of(avatarPath));

    profilesManager.deleteAvatarForIdentity(new byte[1]);

    verify(avatarStorage).delete(avatarPath);
  }

  @Test
  void deleteAvatarForIdentityNotFound() {
    when(profileAvatars.deleteAvatarUrl(any(byte[].class))).thenReturn(Optional.empty());

    profilesManager.deleteAvatarForIdentity(new byte[1]);

    verifyNoInteractions(avatarStorage);
  }

  @Test
  void setV1Avatar() {
    final UUID uuid = UUID.randomUUID();
    final String version = HexFormat.of().formatHex(TestRandomUtil.nextBytes(32));
    final String avatar = "avatar";
    final byte[] commitment = TestRandomUtil.nextBytes(97);

    final VersionedProfileV1 profile = mock(VersionedProfileV1.class);
    when(profile.version()).thenReturn(version);
    when(profile.commitment()).thenReturn(commitment);
    when(profile.avatar()).thenReturn(avatar);

    when(profiles.setV1Avatar(any(UUID.class), anyString(), anyString(), any(byte[].class)))
        .thenReturn(profile);

    profilesManager.setV1Avatar(uuid, version, avatar, commitment);

    verify(commands).del(aryEq(ProfilesManager.getCacheKeyV1(uuid)));
    verify(profiles).setV1Avatar(uuid, version, avatar, commitment);
    verify(setLuaScript).executeBinary(
        argThat(keys ->
            Arrays.equals(keys.get(0), ProfilesManager.getCacheKeyV1(uuid))),
        argThat(args ->
            Arrays.equals(args.get(0), version.getBytes())));
    verifyNoMoreInteractions(setLuaScript);
  }

  @Nested
  class Redis {

    @RegisterExtension
    private static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

    @BeforeEach
    void setUp() throws Exception {
      profilesManager = new ProfilesManager(profiles, profileAvatars, REDIS_CLUSTER_EXTENSION.getRedisCluster(), mock(ScheduledExecutorService.class),
          avatarStorage);
    }

    @ParameterizedTest
    @MethodSource
    void testSetGet(@Nullable final VersionedProfileV1 v1Profile, @Nullable final VersionedProfile v2Profile) {

      final UUID uuid = UUID.randomUUID();

      profilesManager.redisSet(uuid, v2Profile, v1Profile);

      if (v1Profile != null) {

        final Optional<VersionedProfileV1> v1Actual = profilesManager.getV1(uuid, v1Profile.version());

        assertTrue(v1Actual.isPresent());
        assertEquals(v1Profile, v1Actual.get());
      }

      if (v2Profile != null) {
        final Optional<VersionedProfile> v2Actual = profilesManager.get(uuid, v2Profile.version());

        assertTrue(v2Actual.isPresent());
        assertEquals(v2Profile, v2Actual.get());
      }

    }

    static Collection<Arguments> testSetGet() throws Exception {
      final UUID uuid = UUID.randomUUID();
      final byte[] version = TestRandomUtil.nextBytes(32);
      final String versionHex = HexFormat.of().formatHex(version);

      final byte[] name = TestRandomUtil.nextBytes(81);
      final byte[] commitment = new ProfileKey(new byte[32]).getCommitment(new ServiceId.Aci(uuid)).serialize();
      final VersionedProfileV1 profileV1 = new VersionedProfileV1(versionHex, name, null, null, null, null, null, commitment);

      final VersionedProfile profileV2 = new VersionedProfile(version, TestRandomUtil.nextBytes(128),
          TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(64),
          TestRandomUtil.nextBytes(32), commitment);

      return List.of(
          Arguments.argumentSet("only v1", profileV1, null),
          Arguments.argumentSet("only v2", null, profileV2),
          Arguments.argumentSet("both", profileV1, profileV2)
      );
    }
  }

}

