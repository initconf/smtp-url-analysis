# smtp-url-analysis

A Zeek package for comprehensive SMTP and phishing analysis. Extracts URLs from emails, tracks clicks in HTTP traffic, detects suspicious URIs, matches against malicious indicators, and monitors for credential theft.

Works in both **cluster** and **standalone** modes.

> **Version:** 3.0 &nbsp;&middot;&nbsp; **License:** BSD 3-Clause &nbsp;&middot;&nbsp; **Author:** Aashish Sharma

---

## Installation

```bash
zkg install smtp-url-analysis
```

Or load directly in your Zeek configuration:

```zeek
@load smtp-url-analysis/scripts
```

---

## Features

### URL Extraction & Logging

Extracts URLs from email MIME bodies and logs them to `smtpurl_links.log`.

**Script:** `log-smtp-urls.zeek`

| Field | Type | Description |
|-------|------|-------------|
| `ts` | `time` | Timestamp of the email |
| `uid` | `string` | Connection UID |
| `id` | `conn_id` | Connection 4-tuple |
| `host` | `string` | Extracted hostname from URL |
| `url` | `string` | Full URL |

---

### Clicked URL Tracking

Monitors HTTP traffic for URLs previously seen in SMTP. When a user clicks a link from an email, the event is logged to `smtp_clicked_urls.log`. Uses bloom filters for efficient lookup of expired URLs and supports referrer chain tracking.

**Scripts:** `smtp-url-clicks.zeek`, `log-clicked-urls.zeek`

| Field | Type | Description |
|-------|------|-------------|
| `ts` | `time` | HTTP request timestamp |
| `uid` | `string` | HTTP connection UID |
| `id` | `conn_id` | HTTP connection 4-tuple |
| `host` | `string` | Hostname from URL |
| `url` | `string` | Clicked URL |
| `mail_ts` | `time` | Original email timestamp |
| `mail_uid` | `string` | Original email connection UID |
| `from` | `string` | Email sender |
| `to` | `string` | Email recipient |
| `subject` | `string` | Email subject |
| `referrer` | `string` | Referrer chain |

---

### Sensitive URI Detection

Identifies suspicious patterns in URLs extracted from emails.

**Script:** `smtp-sensitive-uris.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::BogusSiteURL` | Domain contains your org's domain as a substring but isn't a legitimate subdomain (typosquatting) |
| `SMTPurl::DottedURL` | URL contains an embedded IP address instead of a domain name |
| `SMTPurl::SensitiveURI` | URL matches configurable suspicious text patterns |
| `SMTPurl::WatchedFileType` | URL points to a suspicious file extension |
| `SMTPurl::Suspicious_File_URL` | Suspicious file URL detected |
| `SMTPurl::Suspicious_Embedded_Text` | Suspicious text found embedded in URL |

---

### Malicious Indicator Matching

Reads indicators from a tab-separated feed file via the Zeek Input Framework. Supports live updates (file re-read on change, no Zeek restart needed). Matches indicators against all SMTP fields: mailfrom, from, to, rcptto, reply_to, subject, relay path IPs, attachment names, and URLs.

**Script:** `smtp-malicious-indicators.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::Malicious_Mailfrom` | Mailfrom matches an indicator |
| `SMTPurl::Malicious_from` | From field matches an indicator |
| `SMTPurl::Malicious_Mailto` | To field matches an indicator |
| `SMTPurl::Malicious_rcptto` | Rcptto matches an indicator |
| `SMTPurl::Malicious_reply_to` | Reply-to matches an indicator |
| `SMTPurl::Malicious_subject` | Subject matches an indicator |
| `SMTPurl::Malicious_Decoded_Subject` | Decoded subject matches an indicator |
| `SMTPurl::Malicious_Path` | Relay path IP matches an indicator |
| `SMTPurl::Malicious_Attachment` | Attachment name matches an indicator |
| `SMTPurl::Malicious_MD5` | Attachment MD5 matches an indicator |
| `SMTPurl::Malicious_URL` | URL matches an indicator |
| `SMTPurl::Malicious_Indicator` | General indicator match |

---

### File Download Detection

Detects when a URL from an email is clicked and results in a file download of a watched MIME type.

**Script:** `smtp-file-download.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::FileDownload` | Clicked email URL resulted in downloading a watched file type |

---

### HTTP Sensitive POST Detection

Detects HTTP POST requests containing credentials, particularly when the POST target was reached via a phishing link from email.

**Script:** `http-sensitive_POSTs.zeek`

| Notice | Description |
|--------|-------------|
| `SMTP::SensitivePOST` | POST request containing password or credential data |
| `SMTP::SensitivePasswd` | Credentials match site domain and meet password complexity requirements |

> [!NOTE]
> These notices use the `SMTP::` namespace rather than `SMTPurl::`.

---

### SMTP Threshold Monitoring

Tracks sender activity (recipient counts, subjects, message origins) and flags anomalous sending patterns. Supports whitelisting known bulk senders via a feed file.

**Script:** `smtp-thresholds.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::TargetedSubject` | External subject targeting many recipients |
| `SMTPurl::bcc_HighVolumeSubject` | High BCC volume for a subject |
| `SMTPurl::SubjectMassMail` | Internal subject associated with mass mailing |
| `SMTPurl::InternalBCCSender` | Internal sender using high-volume BCC |
| `SMTPurl::InternalMassMail` | Internal sender mass mailing |
| `SMTPurl::ExternalBCCSender` | External sender using high-volume BCC |
| `SMTPurl::ExternalMassMail` | External sender mass mailing |
| `SMTPurl::SMTP_Invalid_rcptto` | Invalid recipient detected |
| `SMTPurl::ManyMsgOrigins` | Single sender, messages from many source IPs |

---

### Click Tracking & Spoof Detection

Additional notices generated during URL click analysis and sender verification.

**Script:** `smtp-url-clicks.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::URLClick` | Email URL was clicked (seen in HTTP) |
| `SMTPurl::RareURLClick` | Rarely seen email URL was clicked |
| `SMTPurl::HTTPSensitivePOST` | Sensitive POST on a tracked phishing destination |
| `SMTPurl::AddressSpoofer` | Sender address spoofing detected |
| `SMTPurl::NameSpoofer` | Sender name spoofing detected |
| `SMTPurl::HistoricallyNewAttacker` | Historically new attacker detected |

---

### Email Body Analysis

**Script:** `log-smtp-urls.zeek`

| Notice | Description |
|--------|-------------|
| `SMTPurl::MsgBody` | Suspicious text combined with "click here" found in email body |

---

### RFC 2047 Subject Decoding

Decodes encoded email subjects per RFC 2047, ensuring analysis and indicator matching work on the actual intended text.

**Script:** `smtp-decode-rfc2047.zeek`

---

## Configuration

All settings are in **`scripts/configure-variables-in-this-file.zeek`**. Review and modify these for your environment.

> [!IMPORTANT]
> You **must** set `site_domain` and `site_sub_domains` to your organization's domain for `BogusSiteURL` detection to work correctly.

### Site Identity

```zeek
redef site_domain: pattern = /example\.com|example\.org/;
redef site_sub_domains: pattern = /.*\.(example\.com|example\.org)(:[0-9]+|$)/;
```

### Suspicious Patterns

```zeek
# File extensions to flag in URLs
redef suspicious_file_types += /\.xls$|\.pdf$|\.doc$|\.exe$|\.zip$/;

# Text patterns to flag in URLs
redef suspicious_text_in_url += /googledoc|googledocs|auth\.example\.com\.[a-zA-Z0-9]+/;

# Text patterns to flag in email bodies
redef suspicious_text_in_body += /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]/;
```

### False Positive Suppression

```zeek
# File types to ignore
redef ignore_file_types += /\.gif$|\.png$|\.jpg$/;

# Links to ignore
redef ignore_fp_links += /support\.proofpoint\.com/;
redef ignore_site_links += /example\.com\/|example\.com$/;

# Ignore alerts from mail relay subnets
redef ignore_mail_originators += { 10.0.0.0/8 };

# Ignore alerts from specific senders
redef ignore_mailfroms += /zeek@|noreply@/;
```

### Malicious Indicator Feed

```zeek
redef SMTPurl::smtp_indicator_feed = "/feeds/smtp_malicious_indicators.out";
```

### File Download Monitoring

```zeek
redef SMTPurl::watch_mime_types += /application\/x-dosexec|application\/zip|application\/pdf/;
```

### Notifications

```zeek
redef batch_notice_email = "security-team@example.com";
```

---

## Feed File Format

The malicious indicator feed is a **tab-separated** file with two fields: `indicator` and `description`. A sample is provided at `scripts/feeds/smtp_malicious_indicators.out`.

> [!TIP]
> The feed is read via the Zeek Input Framework with `REREAD` mode. Additions or removals to the file take effect automatically without restarting Zeek.

```text
#fields	indicator	description
"At Your Service" <service@example.com>	Known phishing sender
badsender@example.com	Compromised account
f402e0713127617bda852609b426caff	Malicious attachment hash
HelpDesk	Suspicious subject keyword
```

> [!WARNING]
> Fields **must** be tab-separated. Ensure there are no trailing spaces or mixed delimiters.

---

## Logs

| Log File | Description |
|----------|-------------|
| `smtpurl_links.log` | All URLs extracted from email bodies |
| `smtp_clicked_urls.log` | Email URLs that were later accessed via HTTP |

---

## License

BSD 3-Clause License

Copyright (c) Aashish Sharma and Lawrence Berkeley National Laboratory.
