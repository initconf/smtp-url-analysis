# @TEST-EXEC: zeek -r $TRACES/HTTPSensitivePOST.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

