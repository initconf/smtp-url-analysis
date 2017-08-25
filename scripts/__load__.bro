module Phish ; 

#redef table_expire_interval = 1 secs ;
#redef table_incremental_step=20000 ; 

@load ./a.bro 
@load ./base-vars.bro 

@load ./log-smtp-urls.bro 
@load ./log-clicked-urls.bro

@load ./smtp-sensitive-uris.bro                 
@load ./smtp-malicious-indicators.bro 

@load ./distribute-smtp-urls-workers.bro
@load ./smtp-url-clicks.bro

@load ./http-sensitive_POSTs.bro
@load ./smtp-file-download.bro

@load ./configure-variables-in-this-file.bro    
