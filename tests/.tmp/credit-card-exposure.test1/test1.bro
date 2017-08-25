# @TEST-EXEC: bro -r $TRACES/credit-cards.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff credit_card_exposure.log

redef CreditCardExposure::use_cc_separators = F;
