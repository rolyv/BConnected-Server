// Copyright 2026 BConnected contributors. SPDX-License-Identifier: AGPL-3.0-only
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.util.Util;

@EnabledIfEnvironmentVariable(named="BCONNECTED_TEST_JDBC_URL",matches=".+")
class RegistrationPostgresTest {
  private PGSimpleDataSource dataSource;
  private ExecutorService executor;
  private PhoneNumberIdentifiersPostgres numbers;
  private VerificationSessionsPostgres sessions;
  private ChangeNumberWaitingPeriodsPostgres waiting;
  private static final Instant NOW=Instant.parse("2026-09-20T00:00:00Z");
  private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);

  @BeforeEach void setUp() throws Exception {
    String url=System.getenv("BCONNECTED_TEST_JDBC_URL");
    if(!url.matches("jdbc:postgresql://(127\\.0\\.0\\.1|localhost):[0-9]+/[A-Za-z0-9_]+_test")) throw new IllegalArgumentException("Isolated local test database required");
    dataSource=new PGSimpleDataSource();dataSource.setURL(url);dataSource.setUser("postgres");
    dataSource.setPassword(System.getenv("BCONNECTED_TEST_POSTGRES_PASSWORD"));
    try(var connection=dataSource.getConnection();var statement=connection.createStatement()) {
      statement.execute(Files.readString(Path.of("../bconnected/migrations/004-registration.sql")));
      statement.execute("TRUNCATE signal.verification_sessions,signal.phone_number_identifiers,signal.change_number_waiting_periods");
    }
    executor=Executors.newFixedThreadPool(12);
    numbers=new PhoneNumberIdentifiersPostgres(dataSource,executor);
    sessions=new VerificationSessionsPostgres(dataSource,CLOCK);
    waiting=new ChangeNumberWaitingPeriodsPostgres(dataSource,CLOCK);
  }
  @AfterEach void tearDown() throws Exception {
    if(executor!=null) {executor.shutdown();assertThat(executor.awaitTermination(15,TimeUnit.SECONDS)).isTrue();}
  }
  private VerificationSession session(String id,long ttl) {
    return new VerificationSession(id,"synthetic-challenge",null,List.of(VerificationSession.Information.PUSH_CHALLENGE),
        List.of(),null,null,false,NOW.toEpochMilli(),NOW.toEpochMilli(),ttl);
  }

  @Test void oneInsertWinsAndUpdateRetainsUpstreamUpsertBehavior() {
    var attempts=new ArrayList<CompletableFuture<Boolean>>();
    for(int i=0;i<30;i++) attempts.add(CompletableFuture.supplyAsync(() -> {
      try {sessions.insert("same",session("same",60));return true;}
      catch(IllegalStateException e) {assertThat(e.getMessage()).isEqualTo("Verification session already exists");return false;}
    },executor));
    assertThat(attempts.stream().map(CompletableFuture::join).filter(Boolean::booleanValue).count()).isEqualTo(1);
    assertThat(sessions.findForKey("same")).contains(session("same",60));
    sessions.update("missing",session("missing",80));
    assertThat(sessions.findForKey("missing")).contains(session("missing",80));
    sessions.remove("same");assertThat(sessions.findForKey("same")).isEmpty();
  }

  @Test void sessionExpiryBoundaryAndPhysicalCleanupMatchUpstream() {
    sessions.insert("boundary",session("boundary",0));
    sessions.insert("expired",session("expired",-1));
    assertThat(sessions.findForKey("boundary")).isPresent();
    assertThat(sessions.findForKey("expired")).isEmpty();
    assertThrows(IllegalStateException.class,()->sessions.insert("expired",session("expired",60)));
    assertThat(sessions.deleteExpired(1)).isEqualTo(1);
    sessions.insert("expired",session("expired",60));
    var later=new VerificationSessionsPostgres(dataSource,Clock.fixed(NOW.plusSeconds(1),ZoneOffset.UTC));
    assertThat(later.findForKey("boundary")).isEmpty();
    assertThat(later.findForKey("expired")).isPresent();
  }

  @Test void stablePhoneIdentitySurvivesWaitingPeriodDeletionAndNewStoreInstance() {
    UUID pni=numbers.getPhoneNumberIdentifier("+18005551234").join();
    waiting.setExpiration(pni,NOW.plusSeconds(60));waiting.delete(pni);
    var other=new PhoneNumberIdentifiersPostgres(dataSource,executor);
    assertThat(other.getPhoneNumberIdentifier("+18005551234").join()).isEqualTo(pni);
    assertThat(other.getPhoneNumber(pni).join()).containsExactly("+18005551234");
    assertThat(other.getPhoneNumber(UUID.randomUUID()).join()).isEmpty();
    assertThat(other.getPhoneNumberIdentifier("+18005555678").join()).isNotEqualTo(pni);
  }

  @Test void equivalentFormsConvergeUnderConcurrentRequests() {
    String current=PhoneNumberUtil.getInstance().format(PhoneNumberUtil.getInstance().getExampleNumber("BJ"),PhoneNumberUtil.PhoneNumberFormat.E164);
    String old=current.replaceFirst("01","");
    assertThat(Util.getAlternateForms(current)).contains(old);
    var second=new PhoneNumberIdentifiersPostgres(dataSource,executor);
    var requests=new ArrayList<CompletableFuture<UUID>>();
    for(int i=0;i<60;i++) requests.add((i%2==0?numbers:second).getPhoneNumberIdentifier(i%2==0?current:old));
    var pnIs=requests.stream().map(CompletableFuture::join).distinct().toList();
    assertThat(pnIs).hasSize(1);
    assertThat(numbers.getPhoneNumber(pnIs.getFirst()).join()).contains(current,old);
  }

  @Test void conflictingExistingAssociationsAreNeverReassignedOrPartiallyWritten() {
    String first="+18005551234",second="+18005555678",missing="+18005557890";
    UUID pni1=numbers.getPhoneNumberIdentifier(first).join(),pni2=numbers.getPhoneNumberIdentifier(second).join();
    assertThat(numbers.setPni(first,List.of(first,second,missing),UUID.randomUUID()).join()).isEqualTo(pni1);
    assertThrows(CompletionException.class,()->numbers.setPni(missing,List.of(missing,second),pni1).join());
    assertThat(numbers.getPhoneNumber(pni1).join()).containsExactly(first);
    assertThat(numbers.getPhoneNumber(pni2).join()).containsExactly(second);
  }

  @Test void overlappingReverseOrderMappingsDoNotDeadlockOrMixIdentities() {
    var requests=new ArrayList<CompletableFuture<UUID>>();
    for(int i=0;i<40;i++) {
      List<String> forms=i%2==0?List.of("+18005551234","+18005555678"):List.of("+18005555678","+18005551234");
      requests.add(numbers.setPni(forms.getFirst(),forms,UUID.randomUUID()));
    }
    assertThat(requests.stream().map(CompletableFuture::join).distinct().toList()).hasSize(1);
  }

  @Test void waitingPeriodsHonorExpiryReplaceAndDelete() {
    UUID account=UUID.randomUUID();
    assertThat(waiting.getExpiration(account)).isEmpty();
    waiting.setExpiration(account,NOW);assertThat(waiting.getExpiration(account)).isEmpty();
    waiting.setExpiration(account,NOW.plusSeconds(60));
    assertThat(waiting.getExpiration(account)).contains(NOW.plusSeconds(60));
    assertThat(waiting.getExpiration(UUID.randomUUID())).isEmpty();
    var later=new ChangeNumberWaitingPeriodsPostgres(dataSource,Clock.fixed(NOW.plusSeconds(60),ZoneOffset.UTC));
    assertThat(later.getExpiration(account)).isEmpty();
    assertThat(later.deleteExpired(1)).isEqualTo(1);
    waiting.setExpiration(account,NOW.plusSeconds(30));waiting.delete(account);
    assertThat(waiting.getExpiration(account)).isEmpty();
  }
}
