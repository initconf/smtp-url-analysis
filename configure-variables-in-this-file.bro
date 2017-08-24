module Phish; 


export {
	global OPTIMIZATION: bool = T ; 
} 

##### smtp_sensitive_uri.bro variables 

	#redef link_already_seen += { "*\.es\.net\/", "*\.jbei\.org\/"};

	redef suspicious_file_types += /\.xls$|\.pdf$|\.doc$|\.docx$|\.rar$|\.exe$|\.zip$/ ; 

	#redef ignore_file_types += /\.gif$|\.png$|\.jpg$|\.xml$|\.PNG$|\.jpeg$|\.css$/ ; 
	redef ignore_file_types += /blahblhablhalblh/ ; 

	redef ignore_fp_links += /GALAKA\.com|support\.proofpoint\.com/ ; 

	#redef ignore_mail_originators += { 128.3.64.0/24, 128.3.65.0/24} ; 
	redef ignore_mailfroms += /bro@|cp-mon-trace|ir-dev|security|ir-alerts|ir-reports/ ; 
	redef ignore_notification_emails += {"ir-dev@lbl.gov", "ir-alerts@lbl.gov", "ir-reports@lbl.gov", "security@lbl.gov", "emailteam@lbl.gov",}; 
	redef ignore_site_links += /es\.net\/|es\.net$|jbei\.org\/|jbei\.org$/ &redef ;

	redef suspicious_text_in_url += /password\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|login\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|googledoc|googledocs|wrait\.ru|login\.lbl\.gov\.htm|login\.lbnl\.gov\.htm/ ; 
	redef suspicious_text_in_body += /[Pp][Ee][Rr][Ss][Oo][Nn][Aa][Ll] [Ee][Mm][Aa][Ll]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Uu][Ss][Ee][Rr] [Nn][Aa][Mm][Ee]|[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]/ ; 


##### 

######### ignore links
redef Phish::ignore_fp_links += /proofpoint\.com|GLAKA\.COM|groups\.google\.com\/a\/lbl\.gov\// ;


##### suspicious links


redef Phish::suspicious_text_in_url += /http(s)?:\/\/[a-zA-Z0-9]+\/(www\.lbl\.gov|password\.lbl\.gov\.|lbnl\.gov|lbl\.gov|login\.lbl\.gov|login\.lbnl\.gov)\/|lbl-gov|lbnl-gov|lbl-us|lbnl-us/ ;

#http://lbnl.11r.us/http.gmail.lbl.gov.idp-Authn-UserPassword.htm
#lbl.uni.me/https.login.lbl.gov.html
redef Phish::suspicious_text_in_url += /password\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|login\.lbl\.gov\.[a-zA-Z0-9]+(\/)?|http\.gmail\.lbl\.gov|http\.password\.lbl\.gov/ ;

#artemasdigital.com/wit/dropbox/proposal
redef Phish::suspicious_text_in_url += /dropbox\/proposal\// ;

redef Phish::suspicious_text_in_url += /\/dropbox\/index\.php|\/certificates\/dropbox|\/dropbox\/proposal\/|\/Dropbox\/dropbox|\/dropbox\/proposal|\/Dropbox\/dropbox\/|\/dropbox\/dpbx\/|\/dropbox\/dropbox\/|\/css\/dropbox\/|\/dropbox\/dropboxcont\.html|\/dropbox\/dpbx|\/db\/box\/|\/themes\/dropbox\/|\/secure-dropbox\/document\/|\/js\/dropbox\/|\/fonts\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox\/|\/dropbox\/dropbox|\/dropbox\/dpbx\/index\.php|\/countto\/dropboxjancag\/|\/certificates\/dropbox\/|\/fonts\/DBZP\/Dropbox\/dropbox|\/dropboxlocation\/|\/dropboxhq\/spool\/index\.php|\/dropbox\/dropbox\/dropbox\/|\/css\/dropbox/  ;


#www.codezmart.com/stage/done/auth/view/share/
#breakwaterconsulting.ca/imagelib/drive/auth/share/index.htmleula
redef Phish::suspicious_text_in_url += /\/auth\/view\/share\/|\/drive\/auth\/share\// ;

#dk42.ru/www.berkeley.edu/Login.htm
redef Phish::suspicious_text_in_url += /http(s)?:\/\/[a-zA-Z0-9]+\.[a-zA-Z0-9]+\/www\.berkeley\.edu\/(L|l)ogin\.htm(l)?/ ;

# blah.blah/www.lbl.gov/
redef Phish::suspicious_text_in_url += /http(s)?:\/\/[a-zA-Z0-9]+\.[a-zA-Z0-9]+\/www\.(lbl|lbnl)\.gov\/(L|l)ogin\.htm(l)?/ ;

#emporioshop.com/ess/lbl-gov/AuthnUserPassword.html
redef Phish::suspicious_text_in_url += /lbl-gov\/AuthnUserPassword\.html/ ;

# dropbox phish

redef Phish::suspicious_text_in_url += /new\/dropbox\/proposal\/LoginVerification\.php|new\/dropbox\/proposal\/|LoginVerification\.php/ ;

redef Phish::suspicious_text_in_url += /auth\.login\.php|authberkeleyedu/ ;
redef Phish::suspicious_text_in_url += /_input_3_.txt|_input_3_adri.txt|wp-content\/uploads\/.*txt$/;

#redef Phish::suspicious_text_in_url += /.*\.lbl\.gov\..*/ ;

#redef Phish::suspicious_text_in_url += /lbla\.gov|lblb\.gov|lblc\.gov|lbld\.gov|lble\.gov|lblf\.gov|lblg\.gov|lblh\.gov|lbli\.gov|lblj\.gov|lblk\.gov|lbll\.gov|lblm\.gov|lbln\.gov|lblo\.gov|lblp\.gov|lblq\.gov|lblr\.gov|lbls\.gov|lblt\.gov|lblu\.gov|lblv\.gov|lblw\.gov|lblx\.gov|lbly\.gov|lblz\.gov|mbl\.gov|nbl\.gov|hbl\.gov|dbl\.gov|lcl\.gov|lfl\.gov|ljl\.gov|lrl\.gov|lbm\.gov|lbn\.gov|lbh\.gov|lbd\.gov|lb1\.gov|ibl\.gov|llbl\.gov|libl\.gov|ldl\.gov|lbi\.gov|1bl\.gov|l-bl\.gov|lb-l\.gov|lbvl\.gov|lbhl\.gov|lgbl\.gov|lvbl\.gov|lbgl\.gov|lhbl\.gov|lbnl\.gov|lnbl\.gov|bl\.gov|ll\.gov|lb\.gov|lbbl\.gov|lbp\.gov|obl\.gov|kbl\.gov|lgl\.gov|lhl\.gov|lnl\.gov|lvl\.gov|pbl\.gov|lbk\.gov|lbo\.gov|l\.bl\.gov|lb\.l\.gov|bll\.gov|llb\.gov|wwlbl\.gov|wwwlbl\.gov|www-lbl\.gov|lblgov|lbl-gov/ ; 


