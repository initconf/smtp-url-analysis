# @TEST-EXEC: zeek -r $TRACES/smtp-malicious-indicators.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

