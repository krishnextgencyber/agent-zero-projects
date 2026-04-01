# JustSaying Security Audit Report

**Repository:** `justeattakeaway/JustSaying`  
**Commit audited:** HEAD of `main` (cloned 2026-04-01)  
**Scope:** .NET message bus library for AWS SNS/SQS  
**Audit date:** 2026-04-01  

---

## CRITICAL

---

### CRIT-1: Decompression Bomb — No Size Limit on Decompressed Data

**File:** `src/JustSaying/Messaging/Compression/GzipMessageBodyCompression.cs:36-47`  
**Severity:** Critical  

```csharp
public string Decompress(string messageBody)
{
    var compressedBytes = Convert.FromBase64String(messageBody);
    using var inputStream = new MemoryStream(compressedBytes);
    using var outputStream = new MemoryStream();
    using (var gZipStream = new GZipStream(inputStream, CompressionMode.Decompress))
    {
        gZipStream.CopyTo(outputStream);  // ← NO SIZE LIMIT
    }
    return Encoding.UTF8.GetString(outputStream.ToArray());
}
```

An attacker who can deliver an SQS/SNS message with a GZIP bomb payload (a tiny compressed payload that expands to gigabytes) will cause the consumer process to exhaust heap memory and crash. Because the `SqsPolicyBuilder` grants `Principal: "*"` with only an `ArnLike` source ARN condition (see HIGH-1), any principal with `sqs:SendMessage` permission can trigger this.

**Fix:** Cap the decompressed output size. For example:
```csharp
const int MaxDecompressedBytes = 10 * 1024 * 1024; // 10 MB
using var limited = new LimitStream(outputStream, MaxDecompressedBytes);
gZipStream.CopyTo(limited); // throws if exceeded
```
Or maintain a running byte counter inside the copy loop and throw `InvalidOperationException` if exceeded.

---

### CRIT-2: Full Message Body Leaked in Exceptions and Logs

**Files:**
- `src/JustSaying/AwsTools/MessageHandling/SqsMessagePublisher.cs:59`
- `src/JustSaying/AwsTools/MessageHandling/SnsMessagePublisher.cs:64`
- `src/JustSaying/AwsTools/MessageHandling/Dispatch/MessageDispatcher.cs:141,159`

```csharp
// SqsMessagePublisher.cs:59 — full body in exception message:
throw new PublishException(
    $"Failed to publish message to SQS. {nameof(request.QueueUrl)}: {request.QueueUrl}," +
    $"{nameof(request.MessageBody)}: {request.MessageBody}", ex);

// SnsMessagePublisher.cs:64 — full message payload in exception:
throw new PublishException(
    $"Failed to publish message to SNS. Topic ARN: '{request.TopicArn}', " +
    $"Subject: '{request.Subject}', Message: '{request.Message}'.", ex);

// MessageDispatcher.cs:141 — message body logged at Warning level:
_logger.LogWarning(ex, "... Message body: '{MessageBody}'.", ..., messageContext.Message.Body);

// MessageDispatcher.cs:159 — message body logged at Error level:
_logger.LogError(ex, "Error deserializing message with Id '{MessageId}' and body '{MessageBody}'.",
    ..., messageContext.Message.Body);
```

Full message payloads (potentially containing PII, financial data, auth tokens) are written to application logs and embedded in exception messages. These exceptions also propagate into OpenTelemetry spans (see MED-3). This violates least-privilege logging and common compliance requirements (GDPR, PCI-DSS, HIPAA).

**Fix:** Remove `{MessageBody}` / `{request.MessageBody}` / `{request.Message}` from all log and exception strings. Log only the message ID and type name.

---

## HIGH

---

### HIGH-1: Overly Permissive SNS Topic Policy (`Principal: "*"`)

**File:** `src/JustSaying/AwsTools/MessageHandling/SnsPolicyBuilder.cs:20-48`  
**Severity:** High  

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "*" },
  "Action": [
    "sns:GetTopicAttributes",
    "sns:SetTopicAttributes",
    "sns:AddPermission",
    "sns:RemovePermission",
    "sns:DeleteTopic",
    "sns:Subscribe",
    "sns:Publish"
  ],
  "Condition": { "StringEquals": { "AWS:SourceOwner": "<accountId>" } }
}
```

The first statement grants **any IAM principal within the account** the ability to `DeleteTopic`, `SetTopicAttributes`, `AddPermission`, and `RemovePermission`. `AWS:SourceOwner` restricts to the account, but does not limit to specific roles. A compromised low-privilege principal (e.g., a Lambda or EC2 instance profile) in the same AWS account can delete the topic or add rogue subscribers.

**Fix:** Replace `"AWS": "*"` with the specific IAM role ARN(s) that JustSaying runs under. Remove destructive actions (`DeleteTopic`, `SetTopicAttributes`, `AddPermission`, `RemovePermission`) from the runtime policy—these should be managed by IaC (CDK/CloudFormation/Terraform), not granted to the application at runtime.

---

### HIGH-2: Strong-Name Private Key (`.snk`) Committed to Git

**File:** `justeat-oss.snk` (596 bytes, tracked in git)  
**Severity:** High  

```
git log -- justeat-oss.snk
→ 8c48cfff Add strong name key
```

The RSA private key used to sign NuGet packages is committed in the repository. Anyone with read access can extract this key, sign arbitrary assemblies with the same strong-name identity, and substitute malicious DLLs in environments that rely on strong-name verification. The public key is exposed in `Directory.Build.props` (`<JustSayingKey>`), confirming this is the active signing key.

**Fix:**
1. Rotate the key immediately and publish a new signed package.
2. Add `*.snk` to `.gitignore`.
3. Store the private key in CI secrets (GitHub Actions secret, Azure Key Vault, AWS Secrets Manager).
4. Use delay-signing for local development builds.

---

### HIGH-3: No HTTPS Enforcement on `WithServiceUrl` / `ServiceUri`

**File:** `src/JustSaying/Fluent/AwsClientFactoryBuilder.cs:149-187`  
**File:** `src/JustSaying/AwsTools/DefaultAwsClientFactory.cs:48-67`  
**Severity:** High  

```csharp
public AwsClientFactoryBuilder WithServiceUrl(string url)
    => WithServiceUri(new Uri(url, UriKind.Absolute)); // accepts http://

// DefaultAwsClientFactory — passed directly to AWS SDK:
config.ServiceURL = ServiceUri.ToString();
```

The API accepts any absolute URI including plaintext `http://`. While primarily used for LocalStack in testing, there is no guard preventing use of `http://` in production, meaning AWS credentials (SigV4 signed headers) and full message bodies would be transmitted unencrypted.

**Fix:** In `WithServiceUri`, assert `uri.Scheme == Uri.UriSchemeHttps` unless an explicit testing override is provided. Add `[Obsolete]`/doc comments noting `WithServiceUrl` is for local testing only.

---

### HIGH-4: `NuGetAuditMode=direct` — Transitive Dependency CVEs Not Scanned

**File:** `Directory.Build.props:30`  
**Severity:** High  

```xml
<NuGetAuditMode>direct</NuGetAuditMode>
```

Only direct package references are checked against the NuGet vulnerability advisory database. Transitive dependencies pulled in by `AWSSDK.*`, `Newtonsoft.Json`, `OpenTelemetry`, and `StructureMap` are silently excluded from vulnerability scanning.

**Fix:** Change to `<NuGetAuditMode>all</NuGetAuditMode>` and address any newly surfaced advisories.

---

## MEDIUM

---

### MED-1: Content-Encoding Attribute Accepted From Untrusted Message Source Without Allowlist

**File:** `src/JustSaying/AwsTools/MessageHandling/InboundMessageConverter.cs:42-56`  
**Severity:** Medium  

```csharp
private string ApplyBodyDecompression(string body, MessageAttributes attributes)
{
    var contentEncoding = attributes.Get(MessageAttributeKeys.ContentEncoding);
    if (contentEncoding is not null)
    {
        var decompressor = _compressionRegistry.GetCompression(contentEncoding.StringValue);
        body = decompressor.Decompress(body);  // ← attacker-controlled encoding selection
    }
    return body;
}
```

The `Content-Encoding` attribute value comes directly from the received SQS message and is used to select the decompressor. This is the primary trigger for CRIT-1 (decompression bomb). An attacker who can post to the queue sets `Content-Encoding: gzip+base64` and sends a bomb payload.

**Fix:** Validate `contentEncoding.StringValue` against a strict allowlist (e.g., `ContentEncodings.GzipBase64`) before dispatching to any decompressor. Reject messages with unknown encodings.

---

### MED-2: Bare `catch { // ignored }` in `IsSnsPayload` Swallows Critical Errors

**File:** `src/JustSaying/AwsTools/MessageHandling/InboundMessageConverter.cs:118-147`  
**Severity:** Medium  

```csharp
private static bool IsSnsPayload(string body)
{
    try { ... }
    catch
    {
        // ignored
    }
    return false;
}
```

A bare `catch` that silently discards all exceptions can hide `OutOfMemoryException`, `StackOverflowException`, or thread-abort scenarios. If the JSON parse fails for a legitimate structural reason, the error is silently swallowed and the message is misrouted rather than triggering error handling.

**Fix:** Catch only `JsonException`. Re-throw `OutOfMemoryException`, `StackOverflowException`, and `OperationCanceledException`.

---

### MED-3: Full Stack Traces Written to OpenTelemetry Spans

**File:** `src/JustSaying/AwsTools/MessageHandling/Dispatch/MessageDispatcher.cs:79-88`  
**Severity:** Medium  

```csharp
activity.AddEvent(new ActivityEvent("exception",
    tags: new ActivityTagsCollection
    {
        { "exception.type", ex.GetType().FullName },
        { "exception.message", ex.Message },
        { "exception.stacktrace", ex.ToString() },  // ← full stack trace in telemetry
    }));
```

Full exception stack traces (including assembly paths, framework versions, and potentially message content embedded in the exception chain via CRIT-2) are emitted into OTel spans and exported to any configured collector. If the `PublishException` containing a message body (CRIT-2) propagates here, the body is in the trace.

**Fix:** Strip or scrub `exception.stacktrace`. Consider a configurable `IActivityExceptionEnricher` interface to let operators control what is emitted.

---

### MED-4: Deserializer Returns `null` Without Guard, Propagates as NRE

**File:** `src/JustSaying/Messaging/MessageSerialization/NewtonsoftMessageBodySerializer\`1.cs:57-60`  
**Severity:** Medium  

```csharp
public Message Deserialize(string message)
{
    return JsonConvert.DeserializeObject<T>(message, _settings);
    // returns null for JSON literal "null" — no null guard
}
```

`JsonConvert.DeserializeObject<T>` returns `null` when the input is the JSON literal `"null"`. The return value is passed unchecked into `new InboundMessage(result, attributes)` and then dispatched through middleware, causing a `NullReferenceException` deep in the pipeline rather than a clean, observable error.

**Fix:** Throw `MessageFormatNotSupportedException` (or `JsonException`) if the deserialized result is `null`.

---

### MED-5: `StructureMap 4.6.0` — Unmaintained DI Container, No Security Patches

**File:** `Directory.Packages.props`  
**Severity:** Medium  

`StructureMap 4.6.0` (last release 2019) is a first-class supported DI extension. The package is no longer maintained and receives no security patches. It pulls in transitive dependencies that are similarly unmaintained.

**Fix:** Deprecate `JustSaying.Extensions.DependencyInjection.StructureMap` and redirect users to `JustSaying.Extensions.DependencyInjection.Microsoft`. If StructureMap support must be retained, migrate to Lamar (its actively maintained successor).

---

## LOW

---

### LOW-1: `Newtonsoft.Json` Pinned to `13.0.1` (March 2022)

**File:** `Directory.Packages.props`  
**Severity:** Low  

```xml
<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />
```

Pinned to a fixed version from 2022. No critical CVEs are currently open, but pinning prevents consumers from picking up patch releases. The Newtonsoft serializer is still part of the public API.

**Fix:** Bump to `13.0.3` (current latest patch). Document that `SystemTextJsonMessageBodySerializer` is the preferred, more secure serializer and consider marking the Newtonsoft variant `[Obsolete]`.

---

### LOW-2: `WithServiceUrl` Lacks HTTPS Scheme Validation and Testing-Only Documentation

**File:** `src/JustSaying/Fluent/AwsClientFactoryBuilder.cs:149-156`  
**Severity:** Low  

```csharp
public AwsClientFactoryBuilder WithServiceUrl(string url)
{
    if (url == null) throw new ArgumentNullException(nameof(url));
    return WithServiceUri(new Uri(url, UriKind.Absolute));
}
```

No scheme validation; no documentation that this is intended for testing/LocalStack only.

**Fix:** Add XML doc comment, add `[EditorBrowsable(EditorBrowsableState.Never)]`, and validate scheme is HTTPS in non-test paths.

---

### LOW-3: Default 30-Second SQS Visibility Timeout Enables Silent Message Duplication

**File:** `src/JustSaying/AwsTools/JustSayingConstants.cs:17`  
**Severity:** Low  

```csharp
public static TimeSpan DefaultVisibilityTimeout => TimeSpan.FromSeconds(30);
```

If a handler exceeds 30 seconds, SQS makes the message visible again, causing potential duplicate processing. `BackoffMiddleware` mitigates this but is opt-in. In financial or state-changing contexts, silent duplication has security implications.

**Fix:** Document clearly that handlers exceeding 30s must use `BackoffMiddleware` or extend visibility manually. Consider increasing the default or surfacing a clear warning when handler execution approaches the timeout.

---

## INFORMATIONAL

---

### INFO-1: Strong-Name Public Key in Build Props — Rotation Required After HIGH-2

After rotating the `.snk` key, update `<JustSayingKey>` in `Directory.Build.props` and publish a new signed package version. Consumers using strong-name verification should re-verify against the new key.

---

### INFO-2: `NuGetAuditMode=direct` Scope (see HIGH-4)

Already addressed in HIGH-4.

---

### INFO-3: `TreatWarningsAsErrors=true` — Positive Security Posture

`Directory.Build.props` sets `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`. This prevents silent API surface regressions and forces Roslyn analyzer warnings to be addressed. Good baseline.

---

### INFO-4: ExactlyOnce Lock Key Derives From Message Content

**File:** `src/JustSaying/Messaging/Middleware/ExactlyOnce/ExactlyOnceMiddleware.cs`

The lock key for exactly-once deduplication is derived from message content. If consumers implement `IMessageLockStore` against a backend vulnerable to key injection (e.g., Redis with unsanitized keys, DynamoDB with crafted partition keys), message content could be a vector. This is a design boundary concern.

**Recommendation:** Document that lock key values originate from message content and that backing store implementations must sanitize or parameterize key usage.

---

## Summary Table

| ID | Severity | Title |
|----|----------|-------|
| CRIT-1 | **Critical** | Decompression bomb — no size cap on GZIP decompression |
| CRIT-2 | **Critical** | Full message body in logs and exceptions (PII/data leakage) |
| HIGH-1 | **High** | Overly permissive SNS topic policy (`Principal: "*"` with destructive actions) |
| HIGH-2 | **High** | Strong-name private key (`.snk`) committed to git |
| HIGH-3 | **High** | No HTTPS enforcement on `ServiceUri` — plaintext HTTP accepted |
| HIGH-4 | **High** | `NuGetAuditMode=direct` — transitive CVEs not scanned |
| MED-1 | **Medium** | Content-Encoding from untrusted source enables decompression bomb path |
| MED-2 | **Medium** | Bare `catch { // ignored }` swallows critical errors in `IsSnsPayload` |
| MED-3 | **Medium** | Full stack traces written to OTel spans (potential data leakage) |
| MED-4 | **Medium** | Null-returning deserializer unguarded, causes downstream NRE |
| MED-5 | **Medium** | `StructureMap 4.6.0` — unmaintained, no security patches |
| LOW-1 | **Low** | `Newtonsoft.Json 13.0.1` pinned to old patch release |
| LOW-2 | **Low** | `WithServiceUrl` lacks HTTPS scheme validation and testing-only docs |
| LOW-3 | **Low** | Default 30s visibility timeout enables silent message duplication |
| INFO-1 | **Info** | Strong-name public key rotation required after HIGH-2 remediation |
| INFO-2 | **Info** | NuGet audit scope — covered by HIGH-4 |
| INFO-3 | **Info** | `TreatWarningsAsErrors=true` — good security posture |
| INFO-4 | **Info** | ExactlyOnce lock key derives from message content |

---

## Immediate Remediation Priority

1. **CRIT-1** — Add max-bytes cap to `GzipMessageBodyCompression.Decompress`
2. **CRIT-2** — Remove message body from all log statements and exception messages
3. **HIGH-2** — Rotate the committed `.snk` key; add to `.gitignore`
4. **HIGH-1** — Scope SNS topic IAM policy to specific IAM role ARNs; remove destructive actions
5. **HIGH-4** — Set `NuGetAuditMode=all`; address any newly surfaced transitive CVEs
