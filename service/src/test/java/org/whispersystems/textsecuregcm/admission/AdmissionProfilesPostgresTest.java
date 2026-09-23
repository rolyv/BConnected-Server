// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import com.google.auth.ServiceAccountSigner;
import com.google.cloud.storage.Storage;
import com.google.protobuf.ByteString;
import io.dropwizard.auth.*;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.glassfish.jersey.internal.MapPropertiesDelegate;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.chat.profile.*;
import org.signal.libsignal.protocol.ServiceId;
import org.signal.libsignal.zkgroup.*;
import org.signal.libsignal.zkgroup.profiles.*;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.auth.grpc.RequireAuthenticationInterceptor;
import org.whispersystems.textsecuregcm.avatars.GcsAvatarStorage;
import org.whispersystems.textsecuregcm.badges.ProfileBadgeConverter;
import org.whispersystems.textsecuregcm.configuration.BadgesConfiguration;
import org.whispersystems.textsecuregcm.controllers.ProfileController;
import org.whispersystems.textsecuregcm.entities.CreateProfileRequest;
import org.whispersystems.textsecuregcm.entities.ExpiringProfileKeyCredentialProfileResponse;
import org.whispersystems.textsecuregcm.entities.VersionedProfileResponse;
import org.whispersystems.textsecuregcm.grpc.*;
import org.whispersystems.textsecuregcm.identity.*;
import org.whispersystems.textsecuregcm.limits.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.*;

/** Native transactions, actual REST/gRPC dispatch and real libsignal signing; cloud/private entitlement are synthetic. */
@EnabledIfEnvironmentVariable(named="BCONNECTED_TEST_JDBC_URL", matches=".+")
class AdmissionProfilesPostgresTest {
  enum Route { HTTP_SET, HTTP_GET, HTTP_CREDENTIAL, HTTP_BASE, HTTP_PNI, GRPC_SET, GRPC_GET, GRPC_AVATAR }
  enum Change { SUSPEND, UNCONFIRM, VERSION, PASSWORD }
  AdmissionEntitlementGatePostgresTest fixture;
  AuthenticatedDevice principal;
  AccountsManager cache;
  ProfilesManager legacyProfiles;
  ProfilesPostgres nativeProfiles;
  AdmittedProfiles profiles;
  RateLimiter limiter;
  ProfileController controller;
  ProfileAnonymousGrpcService anonymous;
  Storage cloud;
  ServiceAccountSigner signer;
  GcsAvatarStorage avatars;
  ServerSecretParams secret;
  ServerZkProfileOperations zk;
  ClientZkProfileOperations clientZk;
  ProfileKeyCredentialRequestContext credentialContext;
  ProfileKeyCommitment commitment;
  final byte[] version=new byte[32];
  final String versionHex="00".repeat(32);
  final String oldAvatar="profiles/"+Base64.getUrlEncoder().encodeToString(new byte[16]);
  Executor worker=Runnable::run, avatarWorker=Runnable::run;
  Runnable afterConnection=()->{}, afterProfileWrite=()->{}, afterAccountWrite=()->{}, afterClose=()->{}, afterCommit=()->{},
      duringEviction=()->{}, beforeSign=()->{}, afterSign=()->{}, afterDelete=()->{}, afterCredential=()->{};
  AtomicInteger profileWrites=new AtomicInteger(), accountWrites=new AtomicInteger(), profileEvictions=new AtomicInteger();
  DataSource dataSource;
  ApplicationHandler jersey;
  io.grpc.Server server;
  io.grpc.ManagedChannel channel;
  ProfileGrpc.ProfileBlockingStub grpc;
  boolean retainOriginal;

  @BeforeEach void setup() throws Exception {
    fixture=new AdmissionEntitlementGatePostgresTest(); fixture.setup();
    try(var c=fixture.flow.ds.getConnection(); var s=c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/006-profiles.sql")));
      s.execute("TRUNCATE signal.profiles_v1,signal.profiles_v2,signal.profile_avatars");
    }
    secret=ServerSecretParams.generate(); clientZk=new ClientZkProfileOperations(secret.getPublicParams());
    var key=new ProfileKey(new byte[32]); commitment=key.getCommitment(new ServiceId.Aci(fixture.aci));
    credentialContext=clientZk.createProfileKeyCredentialRequestContext(new ServiceId.Aci(fixture.aci),key);
    zk=spy(new ServerZkProfileOperations(secret));
    doAnswer(call->{var value=call.callRealMethod(); afterCredential.run(); return value;})
        .when(zk).issueExpiringProfileKeyCredential(any(),any(),any(),any());
    nativeProfiles=new ProfilesPostgres(fixture.flow.ds,Runnable::run); nativeProfiles.setV1(fixture.aci,storedProfile());
    var account=account(); account.setCurrentProfileVersion(version);
    new AccountsPostgres(fixture.flow.ds,fixture.flow.http.clock,Runnable::run).update(account); refreshPrincipal();
    dataSource=mock(DataSource.class);
    when(dataSource.getConnection()).thenAnswer(_->{
      var actual=fixture.flow.ds.getConnection(); afterConnection.run();
      return Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Connection.class},(_,method,args)->{
        try {
          Object result=method.invoke(actual,args);
          if(method.getName().equals("commit")) afterCommit.run();
          if(method.getName().equals("close")) afterClose.run();
          if(method.getName().equals("prepareStatement") && args[0] instanceof String sql &&
              (sql.startsWith("INSERT INTO signal.profiles") || sql.startsWith("UPDATE signal.accounts"))) {
            return Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{PreparedStatement.class},(_,operation,params)->{
              try {
                Object value=operation.invoke(result,params);
                if(operation.getName().startsWith("execute")) {
                  if(sql.startsWith("INSERT")) {profileWrites.incrementAndGet(); afterProfileWrite.run();}
                  else {accountWrites.incrementAndGet(); afterAccountWrite.run();}
                }
                return value;
              } catch(InvocationTargetException failure) {throw failure.getCause();}
            });
          }
          return result;
        } catch(InvocationTargetException failure) {throw failure.getCause();}
      });
    });
    cache=mock(AccountsManager.class); legacyProfiles=mock(ProfilesManager.class);
    when(cache.getByServiceIdentifier(any())).thenAnswer(call->Optional.of(account()).filter(a->a.isIdentifiedBy(call.getArgument(0))));
    doAnswer(_->{duringEviction.run(); return null;}).when(cache).invalidateCacheAfterAdmittedUpdate(any());
    cloud=mock(Storage.class); signer=mock(ServiceAccountSigner.class);
    when(signer.getAccount()).thenAnswer(_->{beforeSign.run(); return "synthetic@fixture.invalid";});
    when(signer.sign(any())).thenAnswer(_->{afterSign.run(); return new byte[256];});
    when(cloud.delete(any(com.google.cloud.storage.BlobId.class))).thenAnswer(_->{afterDelete.run(); return true;});
    avatars=new GcsAvatarStorage(cloud,"synthetic-private-fixture",signer,task->avatarWorker.execute(task),fixture.flow.http.clock);
    profiles=new AdmittedProfiles(dataSource,new AccountsPostgres(dataSource,fixture.flow.http.clock,Runnable::run),cache,
        _->profileEvictions.incrementAndGet(),avatars,fixture.gate,task->worker.execute(task));
    var rates=mock(RateLimiters.class); limiter=mock(RateLimiter.class); when(rates.getProfileLimiter()).thenReturn(limiter);
    var badges=mock(BadgesConfiguration.class); when(badges.getBadges()).thenReturn(List.of());
    var converter=mock(ProfileBadgeConverter.class);
    controller=new ProfileController(fixture.flow.http.clock,rates,cache,legacyProfiles,null,null,converter,badges,avatars,
        secret,zk,Runnable::run,false,profiles);
    anonymous=new ProfileAnonymousGrpcService(cache,legacyProfiles,converter,avatars,GenericServerSecretParams.generate(),secret,rates,fixture.flow.http.clock,false);
    var live=AccountAuthenticator.withAdmission(fixture.gate); var auth=mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call->retainOriginal?Optional.of(principal):live.authenticate(call.getArgument(0)));
    jersey=new ApplicationHandler(new ResourceConfig().register(io.dropwizard.jersey.validation.FuzzyEnumParamConverterProvider.class)
        .register(org.whispersystems.textsecuregcm.mappers.FeatureUnavailableExceptionMapper.class)
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>().setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class)).register(controller));
    String name=io.grpc.inprocess.InProcessServerBuilder.generateName();
    server=io.grpc.inprocess.InProcessServerBuilder.forName(name).directExecutor().addService(io.grpc.ServerInterceptors.intercept(
        new ProfileGrpcService(fixture.flow.http.clock,cache,legacyProfiles,null,null,badges,avatars,GenericServerSecretParams.generate(),converter,rates,profiles),
        new MockRequestAttributesInterceptor(),new RequireAuthenticationInterceptor(auth))).build().start();
    channel=io.grpc.inprocess.InProcessChannelBuilder.forName(name).directExecutor().build();
    var metadata=new io.grpc.Metadata(); metadata.put(RequireAuthenticationInterceptor.AUTHORIZATION_METADATA_KEY,
        HeaderUtils.basicAuthHeader(fixture.aci.toString(),fixture.flow.input.password()));
    grpc=ProfileGrpc.newBlockingStub(channel).withInterceptors(io.grpc.stub.MetadataUtils.newAttachHeadersInterceptor(metadata));
  }
  @AfterEach void close() throws Exception {
    if(channel!=null) channel.shutdownNow(); if(server!=null) server.shutdownNow();
    if(jersey!=null) jersey.onShutdown(null); if(fixture!=null) fixture.close();
  }
  void refreshPrincipal() {
    var proof=fixture.gate.authorizeDevice(fixture.aci,(byte)1,fixture.flow.input.password());
    principal=new AuthenticatedDevice(fixture.aci,(byte)1,proof.primaryDeviceLastSeen(),proof);
  }
  void prepare(Route route) {
    if(route==Route.GRPC_SET) {
      fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,capabilities}','{\"spqr\":true,\"profiles_v2\":true}'),version=version+1");
      refreshPrincipal();
    }
  }
  VersionedProfileV1 storedProfile() {return new VersionedProfileV1(versionHex,new byte[81],oldAvatar,new byte[60],new byte[156],null,new byte[29],commitment.serialize());}
  CreateProfileRequest publication(boolean updateAvatar) {return new CreateProfileRequest(commitment,versionHex,new byte[81],new byte[60],new byte[156],null,true,!updateAvatar,Optional.empty(),new byte[29]);}
  SetProfileRequest grpcPublication() {return SetProfileRequest.newBuilder().setVersion(ByteString.copyFrom(version))
      .setExpectedCurrentVersion(ByteString.copyFrom(version)).setCommitment(ByteString.copyFrom(commitment.serialize())).setData(ByteString.copyFrom(new byte[]{1,2,3}))
      .setV1Request(SetProfileV1Request.newBuilder().setAvatarChange(SetProfileV1Request.AvatarChange.AVATAR_CHANGE_UNCHANGED).setName(ByteString.copyFrom(new byte[81]))).build();}
  GetProfileRequest grpcRead(UUID aci) {return GetProfileRequest.newBuilder().setVersion(ByteString.copyFrom(version))
      .setAccountIdentifier(org.signal.chat.common.ServiceIdentifier.newBuilder().setIdentityType(org.signal.chat.common.IdentityType.IDENTITY_TYPE_ACI)
          .setUuid(ByteString.copyFrom(UUIDUtil.toBytes(aci)))).build();}
  Account account() {return new AccountsPostgres(fixture.flow.ds,fixture.flow.http.clock,Runnable::run).getByAccountIdentifier(fixture.aci).orElseThrow();}
  String row() throws Exception {try(var c=fixture.flow.ds.getConnection();var s=c.createStatement();var r=s.executeQuery("SELECT to_jsonb(a)::text FROM signal.accounts a WHERE aci='"+fixture.aci+"'")) {r.next();return r.getString(1);}}
  void expire() {fixture.flow.http.advance(4000);}
  ContainerResponse http(String method,String path,Object body,boolean authenticated) throws Exception {
    var request=new ContainerRequest(URI.create("http://localhost/"),URI.create("http://localhost"+path),method,
        mock(jakarta.ws.rs.core.SecurityContext.class),new MapPropertiesDelegate(),jersey.getConfiguration());
    if(authenticated) request.header("Authorization",HeaderUtils.basicAuthHeader(fixture.aci.toString(),fixture.flow.input.password()));
    request.header("User-Agent","Signal-iOS/7.0.0");
    if(body!=null) {request.header("Content-Type","application/json");request.setEntityStream(new java.io.ByteArrayInputStream(SystemMapper.jsonMapper().writeValueAsBytes(body)));}
    return jersey.apply(request).get(10,TimeUnit.SECONDS);
  }
  Object invoke(Route route) throws Exception {return switch(route) {
    case HTTP_SET->http("PUT","/v1/profile",publication(false),true);
    case HTTP_GET->http("GET","/v1/profile/"+fixture.aci+"/"+versionHex,null,true);
    case HTTP_CREDENTIAL->http("GET","/v1/profile/"+fixture.aci+"/"+versionHex+"/"+HexFormat.of().formatHex(credentialContext.getRequest().serialize())+"?credentialType=expiringProfileKey",null,true);
    case HTTP_BASE->http("GET","/v1/profile/"+fixture.aci,null,true);
    case HTTP_PNI->http("GET","/v1/profile/PNI:"+account().getPhoneNumberIdentifier().orElseThrow(),null,true);
    case GRPC_SET->grpc.setProfile(grpcPublication());
    case GRPC_GET->grpc.getProfile(grpcRead(fixture.aci));
    case GRPC_AVATAR->grpc.setV1Avatar(SetV1AvatarRequest.newBuilder().setVersion(versionHex).build());
  };}
  void failure(Route route,int status) throws Exception {
    if(route.name().startsWith("GRPC")) assertThat(assertThrows(StatusRuntimeException.class,()->invoke(route)).getStatus().getCode())
        .isEqualTo(status==401?Status.Code.UNAUTHENTICATED:Status.Code.UNAVAILABLE);
    else assertThat(((ContainerResponse)invoke(route)).getStatus()).isEqualTo(status);
  }
  @ParameterizedTest @EnumSource(Route.class) void actualAuthenticatedRoutesWorkWithNativeState(Route route) throws Exception {
    prepare(route);int before=account().getVersion();Object result=invoke(route);
    if(result instanceof ContainerResponse http) assertThat(http.getStatus()).isEqualTo(200);
    if(route==Route.HTTP_CREDENTIAL) {var cred=((ExpiringProfileKeyCredentialProfileResponse)((ContainerResponse)result).getEntity()).getCredential();
      assertThat(cred).isNotNull();assertThat(clientZk.receiveExpiringProfileKeyCredential(credentialContext,cred)).isNotNull();}
    if(route==Route.HTTP_GET) assertThat(((VersionedProfileResponse)((ContainerResponse)result).getEntity()).name()).isEqualTo(storedProfile().name());
    if(route==Route.GRPC_GET) assertThat(((GetProfileResponse)result).hasLegacyProfile()).isTrue();
    if(route==Route.GRPC_SET) {assertThat(((SetProfileResponse)result).hasResult()).isTrue();assertThat(nativeProfiles.getV2(fixture.aci,version).orElseThrow().data()).containsExactly(1,2,3);}
    if(route==Route.HTTP_SET||route==Route.GRPC_SET||route==Route.GRPC_AVATAR) {
      assertThat(account().getVersion()).isEqualTo(before+1);assertThat(profileEvictions.get()).isEqualTo(1);
      assertThrows(RuntimeException.class,()->principal.admissionAuthorization().requireCurrent(fixture.aci,(byte)1));
    } else assertThat(account().getVersion()).isEqualTo(before);
    verifyNoInteractions(legacyProfiles);verify(cache,never()).getByAccountIdentifier(any());
  }
  @ParameterizedTest @EnumSource(Route.class) void originalDeadlineSurvivesWorkerWait(Route route) throws Exception {
    prepare(route);String original=row();worker=task->{expire();task.run();};failure(route,503);
    assertThat(row()).isEqualTo(original);assertThat(profileWrites.get()).isZero();verifyNoInteractions(cloud,signer);
  }
  @ParameterizedTest @EnumSource(Route.class) void primaryDeviceRequiredAtEveryRoute(Route route) throws Exception {
    prepare(route);retainOriginal=true;principal=new AuthenticatedDevice(fixture.aci,(byte)2,principal.primaryDeviceLastSeen(),principal.admissionAuthorization());
    failure(route,401);assertThat(profileWrites.get()).isZero();verifyNoInteractions(dataSource,cloud,signer);
  }
  @ParameterizedTest @EnumSource(Change.class) void changedLocalStateDuringWaitCannotPublish(Change change) throws Exception {
    worker=task->{change(change);task.run();};failure(Route.HTTP_SET,change==Change.SUSPEND||change==Change.UNCONFIRM?401:503);
    assertThat(profileWrites.get()).isZero();verifyNoInteractions(cloud,signer);
  }
  void change(Change change) {switch(change) {
    case SUSPEND->fixture.sql("UPDATE signal.admissions SET suspended_at=clock_timestamp()");
    case UNCONFIRM->fixture.sql("UPDATE signal.admission_confirmation_outbox SET confirmed_at=NULL");
    case VERSION->fixture.sql("UPDATE signal.accounts SET version=version+1");
    case PASSWORD->fixture.sql("UPDATE signal.accounts SET data=jsonb_set(data,'{devices,0,authToken}','\"rotated\"')");
  }}
  @Test void expiryAfterV2WriteRollsBackBothProfilesAndAccount() throws Exception {
    prepare(Route.GRPC_SET);String original=row();afterProfileWrite=this::expire;failure(Route.GRPC_SET,503);
    assertThat(profileWrites.get()).isPositive();assertThat(row()).isEqualTo(original);assertThat(nativeProfiles.getV1(fixture.aci,versionHex)).contains(storedProfile());assertThat(nativeProfiles.getV2(fixture.aci,version)).isEmpty();
  }
  @Test void expiryAfterAccountWriteRollsBackProfilesAndAccount() throws Exception {
    String original=row();afterAccountWrite=this::expire;failure(Route.HTTP_SET,503);assertThat(accountWrites.get()).isEqualTo(1);
    assertThat(row()).isEqualTo(original);assertThat(nativeProfiles.getV1(fixture.aci,versionHex)).contains(storedProfile());
  }
  @Test void v1DowngradeDeletionRollsBackWithAccountFailure() throws Exception {
    var v2=new VersionedProfile(version,new byte[]{9},null,commitment.serialize());nativeProfiles.setBoth(fixture.aci,storedProfile(),v2,null);
    afterAccountWrite=this::expire;failure(Route.HTTP_SET,503);assertThat(nativeProfiles.getV2(fixture.aci,version)).contains(v2);
  }
  @Test void successfulV1PublicationDeletesStaleV2InSameTransaction() throws Exception {
    nativeProfiles.setBoth(fixture.aci,storedProfile(),new VersionedProfile(version,new byte[]{9},null,commitment.serialize()),null);
    assertThat(((ContainerResponse)invoke(Route.HTTP_SET)).getStatus()).isEqualTo(200);assertThat(nativeProfiles.getV2(fixture.aci,version)).isEmpty();
  }
  @Test void profileGuardCannotChangeDeviceOrIdentityFields() throws Exception {
    String original=row();assertThrows(jakarta.ws.rs.WebApplicationException.class,()->profiles.http(principal,p->{
      p.setV1(storedProfile());p.account().getPrimaryDevice().setUserAgent("forbidden");return ()->true;
    }));assertThat(row()).isEqualTo(original);assertThat(nativeProfiles.getV1(fixture.aci,versionHex)).contains(storedProfile());
  }
  @Test void invalidSecondProfileWriteRollsBackV2AndAccount() throws Exception {
    String original=row();assertThrows(jakarta.ws.rs.WebApplicationException.class,()->profiles.http(principal,p->{
      p.setBoth(new VersionedProfileV1(null,new byte[]{1},null,null,null,null,null,commitment.serialize()),new VersionedProfile(version,new byte[]{1},null,commitment.serialize()),null);return ()->true;
    }));assertThat(nativeProfiles.getV2(fixture.aci,version)).isEmpty();assertThat(row()).isEqualTo(original);
  }
  @Test void staleV2DataHashDoesNotPartiallyUpdateAccount() throws Exception {
    prepare(Route.GRPC_SET);assertThat(grpc.setProfile(grpcPublication()).hasResult()).isTrue();String original=row();
    assertThat(grpc.setProfile(grpcPublication()).hasExpectedDataWriteConflict()).isTrue();assertThat(row()).isEqualTo(original);
  }
  @Test void oldProfileVersionConflictDoesNotWrite() throws Exception {
    prepare(Route.GRPC_SET);String original=row();assertThat(grpc.setProfile(grpcPublication().toBuilder().setExpectedCurrentVersion(ByteString.copyFrom(new byte[]{1})).build()).hasExpectedVersionWriteConflict()).isTrue();
    assertThat(row()).isEqualTo(original);assertThat(profileWrites.get()).isZero();
  }
  @Test void expiryDuringPoolWaitCannotReadOrPublish() throws Exception {afterConnection=this::expire;failure(Route.HTTP_GET,503);assertThat(profileWrites.get()).isZero();}
  @Test void expiryAfterCommitSuppressesSuccessWithoutUndoingProfile() throws Exception {
    int before=account().getVersion();afterCommit=this::expire;failure(Route.HTTP_SET,503);
    assertThat(account().getVersion()).isEqualTo(before+1);assertThat(profileEvictions.get()).isEqualTo(1);verifyNoInteractions(cloud,signer);
  }
  @Test void expiryDuringCloseSuppressesRead() throws Exception {afterClose=this::expire;failure(Route.GRPC_GET,503);}
  @Test void cacheWaitSuppressesAvatarEffectsAfterCommit() throws Exception {duringEviction=this::expire;failure(Route.GRPC_AVATAR,503);assertThat(accountWrites.get()).isEqualTo(1);verifyNoInteractions(cloud,signer);}
  @Test void providerExecutorRechecksBeforeDeletingObject() throws Exception {avatarWorker=task->{expire();task.run();};failure(Route.GRPC_AVATAR,503);assertThat(accountWrites.get()).isEqualTo(1);verifyNoInteractions(cloud,signer);}
  @Test void signerChecksAfterCredentialLookupBeforeIamSigning() throws Exception {
    beforeSign=this::expire;failure(Route.GRPC_AVATAR,503);verify(cloud).delete(any(com.google.cloud.storage.BlobId.class));verify(signer,never()).sign(any());
  }
  @Test void expiryAfterSigningSuppressesForm() throws Exception {afterSign=this::expire;failure(Route.GRPC_AVATAR,503);verify(signer).sign(any());}
  @Test void suspensionAfterDeletionSuppressesPolicy() throws Exception {
    afterDelete=()->change(Change.SUSPEND);failure(Route.GRPC_AVATAR,401);verify(cloud).delete(any(com.google.cloud.storage.BlobId.class));verifyNoInteractions(signer);
  }
  @Test void nativeCredentialIssuanceWaitRetainsOriginalProof() throws Exception {afterCredential=this::expire;failure(Route.HTTP_CREDENTIAL,503);verify(zk).issueExpiringProfileKeyCredential(any(),any(),any(),any());}
  @Test void rejectedWorkerIsUnavailable() throws Exception {worker=_-> {throw new RejectedExecutionException("synthetic");};failure(Route.HTTP_SET,503);verifyNoInteractions(dataSource,cloud,signer);}
  @Test void rejectedProviderWorkerCannotDeleteOrSign() throws Exception {avatarWorker=_-> {throw new RejectedExecutionException("synthetic");};failure(Route.GRPC_AVATAR,503);verifyNoInteractions(cloud,signer);}
  @Test void rateLimitWaitRetainsCallerProof() throws Exception {doAnswer(_->{expire();return null;}).when(limiter).validate(any(UUID.class));failure(Route.HTTP_GET,503);}
  @Test void staleCacheCannotReplaceReadIdentityOrProfile() throws Exception {
    var stale=account();stale.setIdentityKey(new org.signal.libsignal.protocol.IdentityKey(org.signal.libsignal.protocol.ecc.ECKeyPair.generate().getPublicKey()));
    doReturn(Optional.of(stale)).when(cache).getByServiceIdentifier(any());var response=(VersionedProfileResponse)((ContainerResponse)invoke(Route.HTTP_GET)).getEntity();
    assertThat(response.baseProfileResponse().getIdentityKey()).isEqualTo(account().getAccountIdentityKey());verifyNoInteractions(legacyProfiles);
  }
  @Test void selfMutationNeedsFreshRequestAuthentication() throws Exception {invoke(Route.HTTP_SET);assertThat(((ContainerResponse)invoke(Route.HTTP_GET)).getStatus()).isEqualTo(200);}
  @Test void anonymousProfileAndAvatarMethodsStayClosed() throws Exception {
    assertThat(http("GET","/v1/profile/"+fixture.aci+"/"+versionHex,null,false).getStatus()).isEqualTo(503);
    assertThat(http("GET","/v1/profile/"+fixture.aci,null,false).getStatus()).isEqualTo(503);
    for(org.junit.jupiter.api.function.Executable call:List.<org.junit.jupiter.api.function.Executable>of(
        ()->anonymous.getProfile(GetProfileAnonymousRequest.getDefaultInstance()),
        ()->anonymous.getExpiringProfileKeyCredential(GetExpiringProfileKeyCredentialAnonymousRequest.getDefaultInstance()),
        ()->anonymous.getAvatarUploadForm(GetAvatarUploadFormRequest.getDefaultInstance()),
        ()->anonymous.extendAvatarTTL(ExtendAvatarTTLRequest.getDefaultInstance()),()->anonymous.deleteAvatar(DeleteAvatarRequest.getDefaultInstance()),
        ()->grpc.getAvatarCredentials(GetAvatarCredentialsRequest.getDefaultInstance())))
      assertThat(assertThrows(StatusRuntimeException.class,call).getStatus().getCode()).isEqualTo(Status.Code.UNAVAILABLE);
    verifyNoInteractions(dataSource,cache,legacyProfiles,cloud,signer);
  }
  @Test void existingProfileDoesNotBreakAdmittedAccountSettings() {
    var updates = new AdmittedAccountUpdates(new AccountsPostgres(fixture.flow.ds, fixture.flow.http.clock, Runnable::run),
        _ -> {}, fixture.gate, Runnable::run);
    updates.http(principal, account -> account.getPrimaryDevice().setUserAgent("fixture-settings"));
    assertThat(account().getPrimaryDevice().getUserAgent()).isEqualTo("fixture-settings");
    assertThat(account().getCurrentProfileVersion()).contains(version);
  }
  @Test void restAvatarUpdateReturnsGoogleFormAndClearReturnsEmptySuccess() throws Exception {
    var response = http("PUT", "/v1/profile", publication(true), true);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(SystemMapper.jsonMapper().valueToTree(response.getEntity()).path("algorithm").asText()).isEqualTo("GOOG4-RSA-SHA256");
    verify(cloud).delete(any(com.google.cloud.storage.BlobId.class));
    var clear = new CreateProfileRequest(commitment, versionHex, new byte[81], new byte[60], new byte[156], null,
        false, false, Optional.empty(), new byte[29]);
    var cleared = http("PUT", "/v1/profile", clear, true);
    assertThat(cleared.getStatus()).isEqualTo(200); assertThat(cleared.hasEntity()).isFalse();
    assertThat(nativeProfiles.getV1(fixture.aci, versionHex).orElseThrow().avatar()).isNull();
  }
  @Test void grpcV2ReadAndEtagMatchUseNativePublishedData() {
    prepare(Route.GRPC_SET); assertThat(grpc.setProfile(grpcPublication()).hasResult()).isTrue();
    var result = grpc.getProfile(grpcRead(fixture.aci));
    assertThat(result.hasProfile()).isTrue();
    assertThat(result.getProfile().getData().toByteArray()).containsExactly(1,2,3);
    assertThat(grpc.getProfile(grpcRead(fixture.aci).toBuilder().setEtag(result.getProfile().getEtag()).build()).hasEtagMatched()).isTrue();
  }
  @Test void pniCacheCannotResolveToDifferentIdentity() throws Exception {
    doReturn(Optional.of(account())).when(cache).getByServiceIdentifier(any());
    assertThat(http("GET", "/v1/profile/PNI:" + UUID.randomUUID(), null, true).getStatus()).isEqualTo(404);
    verifyNoInteractions(dataSource, legacyProfiles, cloud, signer);
  }
  @Test void distinctTargetSuspensionDoesNotInvalidateCallerOrDiscloseProfile() throws Exception {
    UUID other = UUID.randomUUID();
    fixture.sql("INSERT INTO signal.accounts(aci,pni,number,version,data) SELECT '" + other + "','" + UUID.randomUUID()
        + "','+13055550199',version,data FROM signal.accounts WHERE aci='" + fixture.aci + "'");
    String permit = "33".repeat(32), verification = "44".repeat(32);
    fixture.sql("INSERT INTO signal.admissions SELECT (jsonb_populate_record(NULL::signal.admissions, to_jsonb(a) || jsonb_build_object("
        + "'aci','" + other + "','member_id','" + UUID.randomUUID() + "','signal_operation_id','" + UUID.randomUUID()
        + "','permit_id','\\x" + permit + "','server_verification_session_hash','\\x" + verification + "'))).* FROM signal.admissions a WHERE aci='" + fixture.aci + "'");
    fixture.sql("INSERT INTO signal.admission_confirmation_outbox(permit_id,confirmed_at) VALUES(decode('" + permit + "','hex'),clock_timestamp())");
    nativeProfiles.setV1(other, storedProfile());
    worker = task -> { fixture.sql("UPDATE signal.admissions SET status='SUSPENDED',suspended_at=clock_timestamp() WHERE aci='" + other + "'"); task.run(); };
    assertThat(http("GET", "/v1/profile/" + other + "/" + versionHex, null, true).getStatus()).isEqualTo(404);
    principal.admissionAuthorization().requireCurrent(fixture.aci, (byte)1);
    verifyNoInteractions(legacyProfiles, cloud, signer);
  }
  @Test void unfinishedProviderCallRetainsAdmissionWorkerCapacity() throws Exception {
    try (var workerPool = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new SynchronousQueue<>());
         var callers = Executors.newVirtualThreadPerTaskExecutor()) {
      worker = workerPool;
      var entered = new CountDownLatch(1); var release = new CountDownLatch(1);
      when(cloud.delete(any(com.google.cloud.storage.BlobId.class))).thenAnswer(_ -> { entered.countDown(); release.await(5, TimeUnit.SECONDS); return true; });
      var first = CompletableFuture.supplyAsync(() -> { try { return http("PUT", "/v1/profile", publication(true), true); }
        catch (Exception e) { throw new CompletionException(e); } }, callers);
      try {
        assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
        int writes = accountWrites.get();
        assertThat(http("PUT", "/v1/profile", publication(false), true).getStatus()).isEqualTo(503);
        assertThat(accountWrites.get()).isEqualTo(writes);
      } finally { release.countDown(); }
      assertThat(first.get(5, TimeUnit.SECONDS).getStatus()).isEqualTo(200);
    }
  }
  @Test void actualProfileRowLockWaitRollsBackAccountAndProfile() throws Exception {
    String original=row();try(var executor=Executors.newVirtualThreadPerTaskExecutor();var blocker=fixture.flow.ds.getConnection()) {
      blocker.setAutoCommit(false);try(var s=blocker.createStatement()) {s.execute("SELECT version FROM signal.profiles_v1 FOR UPDATE");}
      var future=CompletableFuture.supplyAsync(()->{try{return (ContainerResponse)invoke(Route.HTTP_SET);}catch(Exception e){throw new CompletionException(e);}},executor);
      try {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);boolean waiting=false;
        while(System.nanoTime()<deadline&&!waiting) {
          waiting=fixture.flow.count("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%INSERT INTO signal.profiles_v1%'")>0;
          if(!waiting) Thread.sleep(10);
        }
        assertThat(waiting).isTrue();expire();
      } finally {blocker.rollback();}
      assertThat(future.get(5,TimeUnit.SECONDS).getStatus()).isEqualTo(503);assertThat(row()).isEqualTo(original);assertThat(nativeProfiles.getV1(fixture.aci,versionHex)).contains(storedProfile());
    }
  }
}
