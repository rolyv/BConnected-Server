/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Retained phone-identity contracts exercised through the native store's public interface. */
class PhoneNumberIdentifiersTest {
  @RegisterExtension
  static final PostgresAccountKeyTestExtension POSTGRES = new PostgresAccountKeyTestExtension();

  private PhoneNumberIdentifierStore phoneNumberIdentifiers;

  @BeforeEach
  void setUp() {
    phoneNumberIdentifiers = POSTGRES.phoneNumbers();
  }

  @Test
  void getPhoneNumberIdentifier() {
    UUID first = phoneNumberIdentifiers.getPhoneNumberIdentifier("+18005551234").join();
    assertEquals(first, phoneNumberIdentifiers.getPhoneNumberIdentifier("+18005551234").join());
    assertNotEquals(first, phoneNumberIdentifiers.getPhoneNumberIdentifier("+18005556789").join());
  }

  @Test
  void assignMultipleFormsAndRetainAcrossNewStore() {
    List<String> forms = List.of("+18005551234", "+18005556789");
    UUID pni = UUID.randomUUID();
    assertEquals(pni, phoneNumberIdentifiers.setPni(forms.getFirst(), forms, pni).join());
    var reopened = POSTGRES.phoneNumbers();
    for (String form : forms) assertEquals(pni, reopened.getPhoneNumberIdentifier(form).join());
    assertEquals(new HashSet<>(forms), new HashSet<>(reopened.getPhoneNumber(pni).join()));
  }

  @Test
  void getPhoneNumberIdentifierExistingMapping() {
    String current = beninNumber();
    String old = current.replaceFirst("01", "");
    UUID previous = phoneNumberIdentifiers.getPhoneNumberIdentifier(old).join();
    assertEquals(previous, phoneNumberIdentifiers.getPhoneNumberIdentifier(current).join());
  }

  @Test
  void conflictingExistingPnisAreNeverReassigned() {
    String first = "+18005551234", second = "+18005556789";
    UUID a = phoneNumberIdentifiers.getPhoneNumberIdentifier(first).join();
    UUID b = phoneNumberIdentifiers.getPhoneNumberIdentifier(second).join();
    assertNotEquals(a, b);
    assertEquals(a, phoneNumberIdentifiers.setPni(first, List.of(first, second), b).join());
    assertEquals(b, phoneNumberIdentifiers.setPni(second, List.of(second, first), a).join());
    assertEquals(List.of(first), phoneNumberIdentifiers.getPhoneNumber(a).join());
    assertEquals(List.of(second), phoneNumberIdentifiers.getPhoneNumber(b).join());
  }

  @Test
  void alternateConflictRollsBackMissingOriginalAndOtherForms() {
    String original = "+18005551234", existing = "+18005556789", other = "+18005554567";
    UUID previous = phoneNumberIdentifiers.getPhoneNumberIdentifier(existing).join();
    UUID proposed = UUID.randomUUID();
    CompletionException failure = assertThrows(CompletionException.class,
        () -> phoneNumberIdentifiers.setPni(original, List.of(original, existing, other), proposed).join());
    assertTrue(failure.getCause() instanceof IllegalStateException);
    assertTrue(phoneNumberIdentifiers.getPhoneNumber(proposed).join().isEmpty());
    assertEquals(List.of(existing), phoneNumberIdentifiers.getPhoneNumber(previous).join());
  }

  @Test
  void sameIdentityCanAddMissingForms() {
    String first = "+18005551234", second = "+18005556789";
    UUID pni = phoneNumberIdentifiers.getPhoneNumberIdentifier(first).join();
    assertEquals(pni, phoneNumberIdentifiers.setPni(second, List.of(second, first), pni).join());
    assertEquals(Set.of(first, second), new HashSet<>(phoneNumberIdentifiers.getPhoneNumber(pni).join()));
  }

  @Test
  void originalNumberMustBeFirst() {
    assertThrows(IllegalArgumentException.class,
        () -> phoneNumberIdentifiers.setPni("+18005551234", List.of(), UUID.randomUUID()));
    assertThrows(IllegalArgumentException.class,
        () -> phoneNumberIdentifiers.setPni("+18005551234", List.of("+18005556789"), UUID.randomUUID()));
  }

  @Test
  void getPhoneNumber() {
    assertTrue(phoneNumberIdentifiers.getPhoneNumber(UUID.randomUUID()).join().isEmpty());
    UUID pni = phoneNumberIdentifiers.getPhoneNumberIdentifier("+18005551234").join();
    assertEquals(List.of("+18005551234"), phoneNumberIdentifiers.getPhoneNumber(pni).join());
  }

  @Test
  void regeneratePhoneNumberIdentifierMappings() {
    String current = beninNumber(), old = current.replaceFirst("01", "");
    UUID pni = UUID.randomUUID();
    Account account = mock(Account.class);
    when(account.getNumber()).thenReturn(Optional.of(current));
    when(account.getPhoneNumberIdentifier()).thenReturn(Optional.of(pni));
    phoneNumberIdentifiers.regeneratePhoneNumberIdentifierMappings(account).join();
    assertEquals(pni, phoneNumberIdentifiers.getPhoneNumberIdentifier(current).join());
    assertEquals(pni, phoneNumberIdentifiers.getPhoneNumberIdentifier(old).join());
    assertEquals(Set.of(current, old), new HashSet<>(phoneNumberIdentifiers.getPhoneNumber(pni).join()));
    when(account.getNumber()).thenReturn(Optional.empty());
    phoneNumberIdentifiers.regeneratePhoneNumberIdentifierMappings(account).join();
    assertEquals(Set.of(current, old), new HashSet<>(phoneNumberIdentifiers.getPhoneNumber(pni).join()));
  }

  private static String beninNumber() {
    return PhoneNumberUtil.getInstance().format(PhoneNumberUtil.getInstance().getExampleNumber("BJ"),
        PhoneNumberUtil.PhoneNumberFormat.E164);
  }
}
