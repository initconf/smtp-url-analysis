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

1) Make sure you substitute (site.org) with your institution domain in configure-variables-in-this-file.bro 
2) 


Alerts:

1) smtp-malicious-indicators.bro - To flag known sensitve Indicators aka smtp intel feed pointed to by  
 - configure-variables-in-this-file.bro  setup path to feed file:
	ex: redef Phish::smtp_indicator_feed = "/feeds/BRO-feeds/smtp_malicious_indicators.out" ;

This should generate following Kinds of notices:

- Malicious_MD5,
- Malicious_Attachment,
- Malicious_Indicator,
- Malicious_Mailfrom,
- Malicious_Mailto,
- Malicious_from,
- Malicious_reply_to,
- Malicious_subject,
- Malicious_rcptto,
- Malicious_path,
- Malicious_Decoded_Subject


Make sure format of above feed file complies to:

##############
#fields indicator       description
"At Your Service" <service@site.org>	Some random comment
badsender@example.com	some random comment
f402e0713127617bda852609b426caff	some bad hash
HelpDesk	some bad subject
#########################################################################
 
Example alert: 
- Phish::Malicious_rcptto
	Aug 24 11:26:06 CPLZuO3KTSDHx9mCC1      174.15.3.146    36906   18.3.1.10    25      -       -       -       tcp     Phish::Malicious_rcptto Malicious rectto :: [indicator=badsender@example.com, description=random test ], badsender@example.com	badsender@example.com	174.15.3.146 18.3.1.10	25      -       bro     Notice::ACTION_EMAIL,Notice::ACTION_LOG 60.000000       F       -       -       -       -       -


2) smtp-sensitive-uris.bro will generate following alerts 

 - SensitiveURI
 - Dotted_URL
 - Suspicious_File_URL
 - Suspicious_Embedded_Text
 - WatchedFileType
 - BogusSiteURL


Example Alert: 

1503599166.565855       CPLZuO3KTSDHx9mCC1      1.1.1.1    36906   2.2.2.2    25      -       -       -       tcp     Phish::BogusSiteURL     Very similar URL to site: http://www.site.org.blah.com/ from  1.1.1.1       -       1.1.1.1    2.2.2.2  25      -       bro     Notice::ACTION_EMAIL,Notice::ACTION_LOG 3600.000000     F       -       -       -       -       -

again see configure-variables-in-this-file.bro for tweaking and tunning 



	
