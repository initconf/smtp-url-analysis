# phish-analysis-no-postgres

These are newer bro policies which subtitue smtp-embedded-urls-cluster and smtp-embedded-urls-bloom.bro 

Primary scope of these bro policies is to give more insights into smtp-analysis esp to track phishing events. 

Following functionality are provided by the script 

1) Works in a cluster and standalone mode 
2) extracts URLs from Emails and logs them to smtpurl_links.log 
3) Tracks these SMTP urls in http analyzer and logs if any of these SMTP URL has been clicked into a file smtp_clicked_urls.log 
4) Reads a file for malicious indicators and generates an alert of any of those inddicators have a HIT in smtp traffic (see below for more details)
5) Generates alerts if suspicious strings are seen in URL (see below for details)
6) Generates  alerts if a SMTP URL is clicked resulting in a file download 


Detail Notes and How-to:


