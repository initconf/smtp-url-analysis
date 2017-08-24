module Phish; 


export {
	global site_domain: pattern = /site.org/ &redef ; 
	global site_like_domain: pattern = /site.org(:[0-9]+|$)/ &redef ; 
} 

##### smtp_sensitive_uri.bro variables 

	#redef link_already_seen += { "*\.es\.net\/", "*\.jbei\.org\/"};

	redef suspicious_file_types += /\.xls$|\.pdf$|\.doc$|\.docx$|\.rar$|\.exe$|\.zip$/ ; 

	#redef ignore_file_types += /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ ; 
	redef ignore_file_types += /blahblhablhalblh/ ; 

	redef ignore_fp_links += /GALAKA\.com|support\.proofpoint\.com/ ; 

	#redef ignore_mail_originators += { 128.3.64.0/24, 128.3.65.0/24} ; 
	redef ignore_mailfroms += /bro@/; 
	redef ignore_notification_emails += {"bro-alerts@site.org",} ; 
	redef ignore_site_links += /es\.net\/|es\.net$|jbei\.org\/|jbei\.org$/ &redef ;

	redef suspicious_text_in_url += /auth\.site\.org\.[a-zA-Z0-9]+(\/)?|login\.site\.orig\.[a-zA-Z0-9]+(\/)?|googledoc|googledocs|wrait\.ru/ ; 
	redef suspicious_text_in_body += /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/ ; 



##### 

######### ignore links
redef Phish::ignore_fp_links += /proofpoint\.com|GLAKA\.COM|groups\.google\.com\/a\/site\.org\// ;


##### suspicious links
redef Phish::suspicious_text_in_url += /dropbox\/proposal\// ;

redef Phish::suspicious_text_in_url += /\/dropbox\/index\.php|\/certificates\/dropbox|\/dropbox\/proposal\/|\/Dropbox\/dropbox|\/dropbox\/proposal|\/Dropbox\/dropbox\/|\/dropbox\/dpbx\/|\/dropbox\/dropbox\/|\/css\/dropbox\/|\/dropbox\/dropboxcont\.html|\/dropbox\/dpbx|\/db\/box\/|\/themes\/dropbox\/|\/secure-dropbox\/document\/|\/js\/dropbox\/|\/fonts\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox\/|\/dropbox\/dropbox|\/dropbox\/dpbx\/index\.php|\/countto\/dropboxjancag\/|\/certificates\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox|\/dropboxlocation\/|\/dropboxhq\/spool\/index\.php|\/dropbox\/dropbox\/dropbox\/|\/css\/dropbox/  ;

redef Phish::suspicious_text_in_url += /\/auth\/view\/share\/|\/drive\/auth\/share\// ;

# dropbox phish

redef Phish::suspicious_text_in_url += /new\/dropbox\/proposal\/LoginVerification\.php|new\/dropbox\/proposal\/|LoginVerification\.php/ ;
redef Phish::suspicious_text_in_url += /auth\.login\.php|authberkeleyedu/ ;


