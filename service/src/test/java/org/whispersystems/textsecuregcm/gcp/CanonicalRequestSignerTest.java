package org.whispersystems.textsecuregcm.gcp;

import static org.junit.jupiter.api.Assertions.*;

import com.google.auth.ServiceAccountSigner;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.ZonedDateTime;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.attachments.GcsAttachmentGenerator;
import org.whispersystems.textsecuregcm.configuration.GcpAttachmentsConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

class CanonicalRequestSignerTest {
  private static final String EMAIL = "bconnected-signal@roly-dev.iam.gserviceaccount.com";

  @Test
  void iamAndLegacySignIdenticalCanonicalBytes() throws Exception {
    var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var key = generator.generateKeyPair().getPrivate();
    var pem = "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(key.getEncoded())
        + "\n-----END PRIVATE KEY-----\n";
    ServiceAccountSigner signer = new ServiceAccountSigner() {
      public String getAccount() { return EMAIL; }
      public byte[] sign(byte[] bytes) {
        try {
          var signature = Signature.getInstance("SHA256withRSA");
          signature.initSign(key);
          signature.update(bytes);
          return signature.sign();
        } catch (Exception e) { throw new AssertionError(e); }
      }
    };
    var request = new CanonicalRequestGenerator("storage.googleapis.com", EMAIL, "/test-bucket")
        .createFor("test-key", ZonedDateTime.parse("2026-09-20T12:00:00Z"), 12345);
    assertEquals(new CanonicalRequestSigner(pem).sign(request), new CanonicalRequestSigner(signer).sign(request));
    var descriptor = new GcsAttachmentGenerator("storage.googleapis.com", "/test-bucket", signer)
        .generateAttachment("test-key", 12345);
    assertTrue(descriptor.signedUploadLocation().startsWith("https://storage.googleapis.com/test-bucket/test-key?"));
    assertTrue(descriptor.signedUploadLocation().contains("X-Goog-Credential=bconnected-signal%40roly-dev.iam.gserviceaccount.com%2F"));
    assertTrue(descriptor.signedUploadLocation().matches(".*&X-Goog-Signature=[0-9a-f]{512}$"));
    assertEquals("1,12345", descriptor.headers().get("x-goog-content-length-range"));
    assertEquals("start", descriptor.headers().get("x-goog-resumable"));
  }

  @Test
  void failedRemoteSigningDoesNotIssueDescriptor() {
    var failure = new IllegalStateException("IAM unavailable");
    ServiceAccountSigner signer = new ServiceAccountSigner() {
      public String getAccount() { return EMAIL; }
      public byte[] sign(byte[] bytes) { throw failure; }
    };
    assertSame(failure, assertThrows(IllegalStateException.class,
        () -> new GcsAttachmentGenerator("storage.googleapis.com", "/test-bucket", signer).generateAttachment("key", 10)));
  }

  @Test
  void configurationRequiresExactlyOneSigningMode() {
    assertTrue(new GcpAttachmentsConfiguration("storage.googleapis.com", EMAIL, "/bucket", null, true).isSigningConfigurationValid());
    assertFalse(new GcpAttachmentsConfiguration("storage.googleapis.com", EMAIL, "/bucket", new SecretString("key"), true).isSigningConfigurationValid());
    assertFalse(new GcpAttachmentsConfiguration("storage.googleapis.com", "person@example.com", "/bucket", null, true).isSigningConfigurationValid());
    assertFalse(new GcpAttachmentsConfiguration("storage.googleapis.com", EMAIL, "/bucket", null, false).isSigningConfigurationValid());
    assertTrue(new GcpAttachmentsConfiguration("storage.googleapis.com", EMAIL, "/bucket", new SecretString("key")).isSigningConfigurationValid());
  }
}
