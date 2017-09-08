hook Notice::policy(n: Notice::Info)
{

  if ( n$note == Phish::BogusSiteURL) 
   { add n$actions[Notice::ACTION_EMAIL];} 

  if ( n$note == Phish::WRITER_POSTGRESQL_CRASH) 
   { add n$actions[Notice::ACTION_EMAIL];} 

#  if ( n$note == Phish::AddressSpoofer ) 
#   { add n$actions[Notice::ACTION_EMAIL];} 

#  if ( n$note == Phish::NameSpoofer) 
#   { add n$actions[Notice::ACTION_EMAIL];} 
  
#  if ( n$note == Phish::HistoricallyNewAttacker) 
#   { add n$actions[Notice::ACTION_EMAIL];} 

} 

