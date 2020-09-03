# @TEST-EXEC: zeek -r $TRACES/HTTP_SensitivePasswd.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

