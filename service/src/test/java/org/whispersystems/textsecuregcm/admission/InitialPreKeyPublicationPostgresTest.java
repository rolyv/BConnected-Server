// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.admission;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.jersey.jackson.JacksonMessageBodyProvider;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.glassfish.jersey.server.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.auth.*;
import org.whispersystems.textsecuregcm.controllers.InitialPreKeyPublicationController;
import org.whispersystems.textsecuregcm.entities.*;
import org.whispersystems.textsecuregcm.identity.*;
import org.whispersystems.textsecuregcm.storage.*;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Real HTTP, native signature validation, SQL ledger/key pools, and deterministic original-proof races. */
@EnabledIfEnvironmentVariable(named="BCONNECTED_TEST_JDBC_URL", matches=".+")
class InitialPreKeyPublicationPostgresTest {
  enum Wait { WORKER, CONNECTION, LEDGER, EC_WRITE, KEM_WRITE, COMMIT, CLOSE }
  enum BindingChange { EPOCH, MEMBER, SIGNAL_OPERATION, PERMIT, PNI }
  AdmissionKeysPostgresTest base;
  AdmittedKeysPostgres keys;
  DataSource dataSource;
  UUID operation;
  Executor worker=Runnable::run;
  Runnable afterConnection=()->{}, afterLedger=()->{}, afterEc=()->{}, afterKem=()->{}, afterCommit=()->{}, afterClose=()->{};
  AtomicInteger keyWrites=new AtomicInteger();
  boolean retainOriginal;
  String runtimeRole;

  @BeforeEach void setup() throws Exception {
    base=new AdmissionKeysPostgresTest();base.setup();operation=UUID.randomUUID();
    try(var c=base.fixture.flow.ds.getConnection();var s=c.createStatement()) {
      s.execute(Files.readString(Path.of("../bconnected/migrations/015-initial-prekey-publications.sql")));
      s.execute("TRUNCATE signal.initial_prekey_publications");
    }
    dataSource=mock(DataSource.class);
    when(dataSource.getConnection()).thenAnswer(_->{
      var actual=base.fixture.flow.ds.getConnection();afterConnection.run();
      if(runtimeRole!=null)try(var statement=actual.createStatement()){statement.execute("SET ROLE "+runtimeRole);}
      return Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Connection.class},(_,method,args)->{
        try {
          var result=method.invoke(actual,args);
          if(method.getName().equals("commit"))afterCommit.run();
          if(method.getName().equals("close"))afterClose.run();
          if(method.getName().equals("prepareStatement")&&args[0] instanceof String sql&&sql.startsWith("INSERT INTO signal.")) {
            return Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{PreparedStatement.class},(_,op,params)->{
              try {
                var value=op.invoke(result,params);
                if(op.getName().startsWith("execute")) {
                  if(sql.contains("initial_prekey_publications"))afterLedger.run();
                  if(sql.contains("single_use_ec_prekeys")){keyWrites.incrementAndGet();afterEc.run();}
                  if(sql.contains("single_use_kem_prekeys")){keyWrites.incrementAndGet();afterKem.run();}
                }
                return value;
              }catch(InvocationTargetException e){throw e.getCause();}
            });
          }
          return result;
        }catch(InvocationTargetException e){throw e.getCause();}
      });
    });
    keys=new AdmittedKeysPostgres(dataSource,task->worker.execute(task));
    var live=AccountAuthenticator.withAdmission(base.fixture.gate);var auth=mock(AccountAuthenticator.class);
    when(auth.authenticate(any())).thenAnswer(call->retainOriginal?Optional.of(base.principal):live.authenticate(call.getArgument(0)));
    base.jersey.onShutdown(null);
    base.jersey=new ApplicationHandler(new ResourceConfig().property(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE,true)
        .register(io.dropwizard.jersey.validation.FuzzyEnumParamConverterProvider.class)
        .register(org.whispersystems.textsecuregcm.mappers.CompletionExceptionMapper.class)
        .register(new JacksonMessageBodyProvider(SystemMapper.jsonMapper()))
        .register(new AuthDynamicFeature(new BasicCredentialAuthFilter.Builder<AuthenticatedDevice>().setRealm("fixture").setAuthenticator(auth).buildAuthFilter()))
        .register(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
        .register(base.controller).register(new InitialPreKeyPublicationController(base.fixture.gate,keys,base.rates)));
  }
  @AfterEach void close() throws Exception {if(base!=null)base.close();}
  ObjectNode body(IdentityType identity) {
    var pq=identity==IdentityType.ACI?base.kem:base.fixture.flow.keys.activation.pniPqLastResortPreKey().orElseThrow();
    var key=new KEMSignedPreKey(2001,pq.publicKey(),pq.signature());
    return SystemMapper.jsonMapper().valueToTree(Map.of("preKeys",List.of(base.ec),"pqPreKeys",List.of(key)));
  }
  ContainerResponse put(UUID op,IdentityType identity,Object body) throws Exception {
    return base.http("PUT","/v1/bconnected/keys/initial/"+op+"?identity="+identity.name().toLowerCase(Locale.ROOT),body);
  }
  int put() throws Exception {return put(operation,IdentityType.ACI,body(IdentityType.ACI)).getStatus();}
  long ledger() {return base.rows("SELECT count(*) FROM signal.initial_prekey_publications");}
  void expire(){base.expire();}
  void consume(IdentityType identity) {
    UUID identifier=identity==IdentityType.ACI?base.fixture.aci:base.pni;
    new SingleUseECPreKeysPostgres(base.fixture.flow.ds,Runnable::run).take(identifier,(byte)1).join().orElseThrow();
    new SingleUseKEMPreKeysPostgres(base.fixture.flow.ds,Runnable::run).take(identifier,(byte)1).join().orElseThrow();
  }
  void counts(IdentityType identity,int count) {
    UUID identifier=identity==IdentityType.ACI?base.fixture.aci:base.pni;
    assertThat(base.rows("SELECT count(*) FROM signal.single_use_ec_prekeys WHERE account_id='"+identifier+"'")).isEqualTo(count);
    assertThat(base.rows("SELECT count(*) FROM signal.single_use_kem_prekeys WHERE account_id='"+identifier+"'")).isEqualTo(count);
  }
  @ParameterizedTest @EnumSource(IdentityType.class) void successfulReplayNeverRepopulatesConsumedKeys(IdentityType identity) throws Exception {
    var response=put(operation,identity,body(identity));assertThat(response.getStatus()).isEqualTo(204);assertThat(response.hasEntity()).isFalse();
    assertThat(ledger()).isEqualTo(1);assertThat(keyWrites.get()).isEqualTo(2);consume(identity);counts(identity,0);
    assertThat(put(operation,identity,body(identity)).getStatus()).isEqualTo(204);assertThat(keyWrites.get()).isEqualTo(2);counts(identity,0);
    verifyNoInteractions(base.legacyKeys);assertThat(base.fixture.requests.get()).isGreaterThanOrEqualTo(3);
  }
  @Test void identitiesUseIndependentInitialSlotsButCannotShareOperation() throws Exception {
    assertThat(put()).isEqualTo(204);
    assertThat(put(operation,IdentityType.PNI,body(IdentityType.PNI)).getStatus()).isEqualTo(409);
    assertThat(put(UUID.randomUUID(),IdentityType.PNI,body(IdentityType.PNI)).getStatus()).isEqualTo(204);
    assertThat(ledger()).isEqualTo(2);counts(IdentityType.ACI,1);counts(IdentityType.PNI,1);
  }
  @Test void differentBodyOrOperationConflictsWithoutRestoringKeys() throws Exception {
    assertThat(put()).isEqualTo(204);consume(IdentityType.ACI);
    var changed=body(IdentityType.ACI);((ObjectNode)changed.path("preKeys").get(0)).put("keyId",777);
    assertThat(put(operation,IdentityType.ACI,changed).getStatus()).isEqualTo(409);
    assertThat(put(UUID.randomUUID(),IdentityType.ACI,body(IdentityType.ACI)).getStatus()).isEqualTo(409);
    counts(IdentityType.ACI,0);assertThat(ledger()).isEqualTo(1);assertThat(keyWrites.get()).isEqualTo(2);
  }
  @Test void canonicalDigestIgnoresJsonFieldAndArrayOrder() throws Exception {
    var payload=body(IdentityType.ACI);var ec2=payload.path("preKeys").get(0).deepCopy();((ObjectNode)ec2).put("keyId",102);
    ((com.fasterxml.jackson.databind.node.ArrayNode)payload.path("preKeys")).add(ec2);
    assertThat(put(operation,IdentityType.ACI,payload).getStatus()).isEqualTo(204);
    var reordered=body(IdentityType.ACI);var array=(com.fasterxml.jackson.databind.node.ArrayNode)reordered.path("preKeys");array.insert(0,ec2);
    assertThat(put(operation,IdentityType.ACI,reordered).getStatus()).isEqualTo(204);assertThat(keyWrites.get()).isEqualTo(2);
  }
  @ParameterizedTest @EnumSource(Wait.class) void originalDeadlineControlsTransactionAndResponse(Wait wait) throws Exception {
    switch(wait) {
      case WORKER->worker=task->{expire();task.run();};case CONNECTION->afterConnection=this::expire;
      case LEDGER->afterLedger=this::expire;case EC_WRITE->afterEc=this::expire;case KEM_WRITE->afterKem=this::expire;
      case COMMIT->afterCommit=this::expire;case CLOSE->afterClose=this::expire;
    }
    assertThat(put()).isEqualTo(503);
    boolean committed=wait==Wait.COMMIT||wait==Wait.CLOSE;
    assertThat(ledger()).isEqualTo(committed?1:0);
    if(!committed)assertThat(new SingleUseKEMPreKeysPostgres(base.fixture.flow.ds,Runnable::run).take(base.fixture.aci,(byte)1).join()).contains(base.kem);
    else {
      afterCommit=()->{};afterClose=()->{};consume(IdentityType.ACI);
      assertThat(put()).isEqualTo(204);counts(IdentityType.ACI,0);assertThat(keyWrites.get()).isEqualTo(2);
    }
  }
  @ParameterizedTest @EnumSource(AdmissionKeysPostgresTest.Change.class) void changedAuthorizationDuringWorkerWaitCannotRecordOperation(AdmissionKeysPostgresTest.Change change) throws Exception {
    worker=task->{base.change(change);task.run();};
    assertThat(put()).isEqualTo(change==AdmissionKeysPostgresTest.Change.SUSPEND||change==AdmissionKeysPostgresTest.Change.UNCONFIRM?401:503);
    assertThat(ledger()).isZero();assertThat(keyWrites.get()).isZero();
  }
  @Test void revokedReplayCannotExposeRecordedSuccess() throws Exception {
    assertThat(put()).isEqualTo(204);consume(IdentityType.ACI);retainOriginal=true;
    base.change(AdmissionKeysPostgresTest.Change.SUSPEND);assertThat(put()).isEqualTo(401);counts(IdentityType.ACI,0);
  }
  @ParameterizedTest @EnumSource(BindingChange.class) void oldOperationCannotMoveToNewAuthoritativeBinding(BindingChange change) throws Exception {
    IdentityType identity=change==BindingChange.PNI?IdentityType.PNI:IdentityType.ACI;
    assertThat(put(operation,identity,body(identity)).getStatus()).isEqualTo(204);consume(identity);
    switch(change) {
      case EPOCH->base.fixture.sql("UPDATE signal.admissions SET approval_epoch=approval_epoch+1");
      case MEMBER->base.fixture.sql("UPDATE signal.admissions SET member_id='"+UUID.randomUUID()+"'");
      case SIGNAL_OPERATION->base.fixture.sql("UPDATE signal.admissions SET signal_operation_id='"+UUID.randomUUID()+"'");
      case PERMIT->base.fixture.sql("DELETE FROM signal.admission_confirmation_outbox; UPDATE signal.admissions SET permit_id=decode('"+"99".repeat(32)+"','hex'); INSERT INTO signal.admission_confirmation_outbox(permit_id,confirmed_at) SELECT permit_id,clock_timestamp() FROM signal.admissions");
      case PNI->base.fixture.sql("UPDATE signal.accounts SET pni='"+UUID.randomUUID()+"',version=version+1");
    }
    assertThat(put(operation,identity,body(identity)).getStatus()).isEqualTo(409);assertThat(ledger()).isEqualTo(1);assertThat(keyWrites.get()).isEqualTo(2);
  }
  @Test void reapprovalMayUseNewOperationWithoutRevivingOldOne() throws Exception {
    assertThat(put()).isEqualTo(204);consume(IdentityType.ACI);base.fixture.sql("UPDATE signal.admissions SET approval_epoch=approval_epoch+1");
    assertThat(put()).isEqualTo(409);assertThat(put(UUID.randomUUID(),IdentityType.ACI,body(IdentityType.ACI)).getStatus()).isEqualTo(204);
    assertThat(ledger()).isEqualTo(2);
  }
  @ParameterizedTest @ValueSource(strings={"empty","missing","unknown","signed","duplicate-ec","duplicate-pq","bad-id","fraction-id","null-key","bad-key","bad-signature","wrong-identity","too-many"})
  void invalidInputDoesNotReachLedgerOrKeyStorage(String kind) throws Exception {
    var payload=body(IdentityType.ACI);
    switch(kind) {
      case "empty"->payload.putArray("preKeys");case "missing"->payload.remove("pqPreKeys");case "unknown"->payload.put("extra",true);case "signed"->payload.putNull("signedPreKey");
      case "duplicate-ec"->((com.fasterxml.jackson.databind.node.ArrayNode)payload.path("preKeys")).add(payload.path("preKeys").get(0).deepCopy());
      case "duplicate-pq"->((com.fasterxml.jackson.databind.node.ArrayNode)payload.path("pqPreKeys")).add(payload.path("pqPreKeys").get(0).deepCopy());
      case "bad-id"->((ObjectNode)payload.path("preKeys").get(0)).put("keyId",-1);
      case "fraction-id"->((ObjectNode)payload.path("preKeys").get(0)).put("keyId",1.5);
      case "null-key"->((ObjectNode)payload.path("preKeys").get(0)).putNull("publicKey");
      case "bad-key"->((ObjectNode)payload.path("pqPreKeys").get(0)).put("publicKey","AA==");
      case "bad-signature"->((ObjectNode)payload.path("pqPreKeys").get(0)).put("signature",Base64.getEncoder().encodeToString(new byte[64]));
      case "wrong-identity"->payload=body(IdentityType.PNI);
      case "too-many"->{var array=(com.fasterxml.jackson.databind.node.ArrayNode)payload.path("preKeys");for(int i=0;i<100;i++){var key=array.get(0).deepCopy();((ObjectNode)key).put("keyId",1000+i);array.add(key);}}
    }
    assertThat(put(operation,IdentityType.ACI,payload).getStatus()).isEqualTo(400);assertThat(ledger()).isZero();verifyNoInteractions(dataSource);
  }
  @Test void strictParserRejectsDuplicatePropertiesAndTrailingDocument() throws Exception {
    var controller=new InitialPreKeyPublicationController(base.fixture.gate,keys,base.rates);
    String body=SystemMapper.jsonMapper().writeValueAsString(body(IdentityType.ACI));
    for(String invalid:List.of(body+" {}",body.replaceFirst("\\{","{\"preKeys\":[],")))
      assertThat(controller.publish(base.principal,operation.toString(),"aci",new java.io.ByteArrayInputStream(invalid.getBytes(java.nio.charset.StandardCharsets.UTF_8))).getStatus()).isEqualTo(400);
    assertThat(ledger()).isZero();verifyNoInteractions(dataSource);
  }
  @ParameterizedTest @ValueSource(strings={"missing-proof","secondary","other-aci"}) void wrongPrincipalFailsBeforeLedger(String kind) throws Exception {
    retainOriginal=true;var p=base.principal;
    base.principal=switch(kind){case "missing-proof"->new AuthenticatedDevice(p.accountIdentifier(),p.deviceId(),p.primaryDeviceLastSeen());
      case "secondary"->new AuthenticatedDevice(p.accountIdentifier(),(byte)2,p.primaryDeviceLastSeen(),p.admissionAuthorization());
      default->new AuthenticatedDevice(UUID.randomUUID(),p.deviceId(),p.primaryDeviceLastSeen(),p.admissionAuthorization());};
    assertThat(put()).isEqualTo(401);verifyNoInteractions(dataSource);assertThat(ledger()).isZero();
  }
  @Test void executorAndRateLimiterWaitFailClosed() throws Exception {
    worker=_-> {throw new RejectedExecutionException();};assertThat(put()).isEqualTo(503);assertThat(ledger()).isZero();
    worker=Runnable::run;doAnswer(_->{expire();return null;}).when(base.limiter).validate(any(UUID.class));assertThat(put()).isEqualTo(503);verifyNoInteractions(dataSource);
  }
  @Test void concurrentExactReplayOnlyReplacesEachPoolOnce() throws Exception {
    try(var callers=Executors.newVirtualThreadPerTaskExecutor()) {
      var tasks=new ArrayList<CompletableFuture<Integer>>();
      for(int i=0;i<8;i++)tasks.add(CompletableFuture.supplyAsync(()->{try{return put();}catch(Exception e){throw new CompletionException(e);}},callers));
      for(var result:tasks)assertThat(result.get(10,TimeUnit.SECONDS)).isEqualTo(204);
    }
    assertThat(ledger()).isEqualTo(1);assertThat(keyWrites.get()).isEqualTo(2);
  }
  @Test void nativeAdvisoryLockWaitConsumesOriginalProof() throws Exception {
    try(var callers=Executors.newVirtualThreadPerTaskExecutor();var blocker=base.fixture.flow.ds.getConnection()) {
      blocker.setAutoCommit(false);
      // Same advisory key used by the native EC pool; make the real transaction wait before its ledger insert.
      long lock=base.fixture.aci.getMostSignificantBits() ^ Long.rotateLeft(base.fixture.aci.getLeastSignificantBits(),17) ^ 0x424345435052454BL;
      try(var s=blocker.prepareStatement("SELECT pg_advisory_xact_lock(?)")){s.setLong(1,lock);s.execute();}
      var pending=CompletableFuture.supplyAsync(()->{try{return put();}catch(Exception e){throw new CompletionException(e);}},callers);
      try {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);boolean waiting=false;
        while(System.nanoTime()<end&&!waiting){waiting=base.rows("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock%'")>0;if(!waiting)Thread.sleep(10);}
        assertThat(waiting).isTrue();expire();
      }finally{blocker.rollback();}
      assertThat(pending.get(5,TimeUnit.SECONDS)).isEqualTo(503);assertThat(ledger()).isZero();
    }
  }
  @Test void legacyReplacementRemainsSeparateFromOwnedLedger() throws Exception {
    assertThat(put()).isEqualTo(204);consume(IdentityType.ACI);
    assertThat(base.http("PUT","/v2/keys",base.publication()).getStatus()).isEqualTo(204);counts(IdentityType.ACI,1);
    consume(IdentityType.ACI);assertThat(put()).isEqualTo(204);counts(IdentityType.ACI,0);assertThat(ledger()).isEqualTo(1);
  }
  @Test void malformedRouteOrNamespaceCannotDefaultToAci() throws Exception {
    for(String suffix:List.of(operation.toString(),operation+"?identity=unknown",operation+"?identity=ACI","bad?identity=aci"))
      assertThat(base.http("PUT","/v1/bconnected/keys/initial/"+suffix,body(IdentityType.ACI)).getStatus()).isEqualTo(400);
    verifyNoInteractions(dataSource);
  }
  @Test void nativeRuntimeRoleCanApplyAndReplayWithOnlySelectInsertOnLedger() throws Exception {
    String role="initial_prekeys_test_"+UUID.randomUUID().toString().replace("-", "");
    base.fixture.sql("CREATE ROLE "+role+" NOLOGIN");
    try {
      base.fixture.sql("GRANT USAGE ON SCHEMA signal TO "+role);
      base.fixture.sql("GRANT SELECT,UPDATE ON signal.accounts,signal.admissions,signal.admission_confirmation_outbox TO "+role);
      base.fixture.sql("GRANT SELECT,INSERT,UPDATE,DELETE ON signal.single_use_ec_prekeys,signal.single_use_kem_prekeys TO "+role);
      base.fixture.sql("GRANT SELECT,INSERT ON signal.initial_prekey_publications TO "+role);
      runtimeRole=role;
      assertThat(put()).isEqualTo(204);consume(IdentityType.ACI);assertThat(put()).isEqualTo(204);counts(IdentityType.ACI,0);
      try(var connection=base.fixture.flow.ds.getConnection();var statement=connection.createStatement()) {
        statement.execute("SET ROLE "+role);
        for(String privilege:List.of("SELECT","INSERT","UPDATE","DELETE","TRUNCATE","REFERENCES","TRIGGER","MAINTAIN")) {
          try(var rows=statement.executeQuery("SELECT has_table_privilege(current_user,'signal.initial_prekey_publications','"+privilege+"'),has_table_privilege(current_user,'signal.initial_prekey_publications','"+privilege+" WITH GRANT OPTION')")) {
            rows.next();assertThat(rows.getBoolean(1)).isEqualTo(privilege.equals("SELECT")||privilege.equals("INSERT"));assertThat(rows.getBoolean(2)).isFalse();
          }
        }
        for(String sql:List.of("UPDATE signal.initial_prekey_publications SET response_status=204 WHERE false",
            "DELETE FROM signal.initial_prekey_publications WHERE false", "TRUNCATE signal.initial_prekey_publications"))
          assertThat(assertThrows(java.sql.SQLException.class,()->statement.execute(sql)).getSQLState()).isEqualTo("42501");
      }
      assertThat(ledger()).isEqualTo(1);
    } finally {runtimeRole=null;base.fixture.sql("DROP OWNED BY "+role);base.fixture.sql("DROP ROLE "+role);}
  }
  @Test void nativePublicationSnapshotCannotSwitchSigningIdentityOrExposeMutableSignature() throws Exception {
    byte[] bytes=SystemMapper.jsonMapper().writeValueAsBytes(body(IdentityType.ACI));
    var publication=InitialPreKeyPublication.parse(new java.io.ByteArrayInputStream(bytes),base.fixture.flow.keys.aci);
    byte[] signature=publication.kem().getFirst().signature();signature[0]^=1;
    assertThat(publication.kem().getFirst().signature()).isNotEqualTo(signature);
    assertThrows(AdmissionKeyGuard.Failure.class,()->keys.publishInitial(base.guard(),IdentityType.PNI,operation,publication));
    assertThat(ledger()).isZero();verifyNoInteractions(dataSource);
  }
  @Test void bodyReadWaitCannotRenewOriginalProof() throws Exception {
    byte[] bytes=SystemMapper.jsonMapper().writeValueAsBytes(body(IdentityType.ACI));
    var body=new java.io.ByteArrayInputStream(bytes){@Override public byte[] readNBytes(int length) throws java.io.IOException {expire();return super.readNBytes(length);}};
    var controller=new InitialPreKeyPublicationController(base.fixture.gate,keys,base.rates);
    var failure=assertThrows(jakarta.ws.rs.WebApplicationException.class,()->controller.publish(base.principal,operation.toString(),"aci",body));
    assertThat(failure.getResponse().getStatus()).isEqualTo(503);assertThat(ledger()).isZero();verifyNoInteractions(dataSource);
  }
  @Test void missingLedgerSchemaFailsClosedWithoutReplacingPools() throws Exception {
    base.fixture.sql("DROP TABLE signal.initial_prekey_publications");assertThat(put()).isEqualTo(503);assertThat(keyWrites.get()).isZero();
  }
}
