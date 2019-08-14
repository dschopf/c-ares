#include "ares-test.h"
#include "dns-proto.h"

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseAReplyExEmptyReply) {
  ares_a_reply *reply = nullptr;

  EXPECT_EQ(nullptr, ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_EQ(nullptr, ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(0, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_addr_count(reply));
  EXPECT_EQ(nullptr, ares_a_reply_ex_get_addr(reply, 0));
  EXPECT_EQ(0, ares_a_reply_ex_get_ttl(reply, 0));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseAReplyExOK) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 0x01020304, {2,3,4,5}));
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  EXPECT_EQ(data, pkt.data());

  ares_a_reply *reply = nullptr;

  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));

  EXPECT_NE(nullptr, reply);
  EXPECT_STREQ("example.com", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_EQ(nullptr, ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_addr_count(reply));

  in_addr *a = reinterpret_cast<in_addr*>(const_cast<char*>(ares_a_reply_ex_get_addr(reply, 0)));
  unsigned long expected_addr = htonl(0x02030405);
  EXPECT_EQ(expected_addr, a->s_addr);
  EXPECT_EQ("2.3.4.5", AddressToString(a, 4));
  EXPECT_EQ(0x01020304, ares_a_reply_ex_get_ttl(reply, 0));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseMalformedAReplyEx) {
  std::vector<byte> data = {
    0x12, 0x34,  // [0:2) qid
    0x84, // [2] response + query + AA + not-TC + not-RD
    0x00, // [3] not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // [4:6) num questions
    0x00, 0x01,  // [6:8) num answer RRs
    0x00, 0x00,  // [8:10) num authority RRs
    0x00, 0x00,  // [10:12) num additional RRs
    // Question
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // [12:20)
    0x03, 'c', 'o', 'm', // [20,24)
    0x00, // [24]
    0x00, 0x01,  // [25:26) type A
    0x00, 0x01,  // [27:29) class IN
    // Answer 1
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // [29:37)
    0x03, 'c', 'o', 'm', // [37:41)
    0x00, // [41]
    0x00, 0x01,  // [42:44) RR type
    0x00, 0x01,  // [44:46) class IN
    0x01, 0x02, 0x03, 0x04, // [46:50) TTL
    0x00, 0x04,  // [50:52) rdata length
    0x02, 0x03, 0x04, 0x05, // [52,56)
  };

  // Invalid RR-len.
  std::vector<byte> invalid_rrlen(data);
  invalid_rrlen[51] = 180;

  ares_a_reply *reply = nullptr;

  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(invalid_rrlen.data(), invalid_rrlen.size(), &reply));
  EXPECT_EQ(nullptr, reply);

  // Truncate mid-question.
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(data.data(), 26, &reply));
  EXPECT_EQ(nullptr, reply);

  // Truncate mid-answer.
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(data.data(), 42, &reply));
  EXPECT_EQ(nullptr, reply);
}

TEST_F(LibraryTest, ParseAReplyExNoData) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a));
  std::vector<byte> data = pkt.data();

  ares_a_reply *reply = nullptr;
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);

  // Again but with a CNAME.
  pkt.add_answer(new DNSCnameRR("example.com", 200, "c.example.com"));
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);
}

TEST_F(LibraryTest, ParseAReplyExVariantA) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("mit.edu", ns_t_a))
    .add_answer(new DNSARR("mit.edu", 52, {18,7,22,69}))
    .add_auth(new DNSNsRR("mit.edu", 292, "W20NS.mit.edu"))
    .add_auth(new DNSNsRR("mit.edu", 292, "BITSY.mit.edu"))
    .add_auth(new DNSNsRR("mit.edu", 292, "STRAWB.mit.edu"))
    .add_additional(new DNSARR("STRAWB.mit.edu", 292, {18,71,0,151}));

  std::vector<byte> data = pkt.data();

  ares_a_reply *reply = nullptr;

  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_NE(nullptr, reply);


  EXPECT_STREQ("mit.edu", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_EQ(nullptr, ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_addr_count(reply));

  in_addr *a = reinterpret_cast<in_addr*>(const_cast<char*>(ares_a_reply_ex_get_addr(reply, 0)));
  unsigned long expected_addr = htonl(0x12071645);
  EXPECT_EQ(expected_addr, a->s_addr);
  EXPECT_EQ("18.7.22.69", AddressToString(a, 4));
  EXPECT_EQ(52, ares_a_reply_ex_get_ttl(reply, 0));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseAReplyExJustCname) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("mit.edu", ns_t_a))
    .add_answer(new DNSCnameRR("mit.edu", 52, "other.mit.edu"));

  std::vector<byte> data = pkt.data();

  ares_a_reply *reply = nullptr;

  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  ASSERT_NE(nullptr, reply);

  EXPECT_STREQ("other.mit.edu", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_STREQ("mit.edu", ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(0, ares_a_reply_ex_get_addr_count(reply));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseAReplyExVariantCname) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("query.example.com", ns_t_a))
    .add_answer(new DNSCnameRR("query.example.com", 200, "redirect.query.example.com"))
    .add_answer(new DNSARR("redirect.query.example.com", 300, {129,97,123,22}))
    .add_auth(new DNSNsRR("example.com", 218, "aa.ns1.example.com"))
    .add_auth(new DNSNsRR("example.com", 218, "ns2.example.com"))
    .add_auth(new DNSNsRR("example.com", 218, "ns3.example.com"))
    .add_auth(new DNSNsRR("example.com", 218, "ns4.example.com"))
    .add_additional(new DNSARR("aa.ns1.example.com", 218, {129,97,1,1}))
    .add_additional(new DNSARR("ns2.example.com", 218, {129,97,1,2}))
    .add_additional(new DNSARR("ns3.example.com", 218, {129,97,1,3}))
    .add_additional(new DNSARR("ns4.example.com", 218, {129,97,1,4}));

  std::vector<byte> data = pkt.data();

  ares_a_reply *reply = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));

  EXPECT_STREQ("redirect.query.example.com", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_STREQ("query.example.com", ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_addr_count(reply));

  in_addr *a = reinterpret_cast<in_addr*>(const_cast<char*>(ares_a_reply_ex_get_addr(reply, 0)));
  unsigned long expected_addr = htonl(0x81617b16);
  EXPECT_EQ(expected_addr, a->s_addr);
  EXPECT_EQ("129.97.123.22", AddressToString(a, 4));
  EXPECT_EQ(200, ares_a_reply_ex_get_ttl(reply, 0));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseAReplyExVariantCnameChain) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("c1.localhost", ns_t_a))
    .add_answer(new DNSCnameRR("c1.localhost", 604800, "c2.localhost"))
    .add_answer(new DNSCnameRR("c2.localhost", 604800, "c3.localhost"))
    .add_answer(new DNSCnameRR("c3.localhost", 604800, "c4.localhost"))
    .add_answer(new DNSARR("c4.localhost", 604800, {8,8,8,8}))
    .add_auth(new DNSNsRR("localhost", 604800, "localhost"))
    .add_additional(new DNSARR("localhost", 604800, {127,0,0,1}))
    .add_additional(new DNSAaaaRR("localhost", 604800,
                              {0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}));

  std::vector<byte> data = pkt.data();

  ares_a_reply *reply = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));

  EXPECT_STREQ("c2.localhost", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(3, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_STREQ("c1.localhost", ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_STREQ("c2.localhost", ares_a_reply_ex_get_alias(reply, 1));
  EXPECT_STREQ("c3.localhost", ares_a_reply_ex_get_alias(reply, 2));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));

  in_addr *a = reinterpret_cast<in_addr*>(const_cast<char*>(ares_a_reply_ex_get_addr(reply, 0)));
  unsigned long expected_addr = htonl(0x08080808);
  EXPECT_EQ(expected_addr, a->s_addr);
  EXPECT_EQ("8.8.8.8", AddressToString(a, 4));
  EXPECT_EQ(604800, ares_a_reply_ex_get_ttl(reply, 0));

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, DISABLED_ParseAReplyExVariantCnameLast) {
  DNSPacket pkt;
  pkt.set_qid(6366).set_rd().set_ra()
    .add_question(new DNSQuestion("query.example.com", ns_t_a))
    .add_answer(new DNSARR("redirect.query.example.com", 300, {129,97,123,221}))
    .add_answer(new DNSARR("redirect.query.example.com", 300, {129,97,123,222}))
    .add_answer(new DNSARR("redirect.query.example.com", 300, {129,97,123,223}))
    .add_answer(new DNSARR("redirect.query.example.com", 300, {129,97,123,224}))
    .add_answer(new DNSCnameRR("query.example.com", 60, "redirect.query.example.com"))
    .add_additional(new DNSTxtRR("query.example.com", 60, {"text record"}));

  std::vector<byte> data = pkt.data();
  ares_a_reply *reply = nullptr;

  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply_ex(data.data(), data.size(), &reply));

  EXPECT_STREQ("redirect.query.example.com", ares_a_reply_ex_get_name(reply));
  EXPECT_EQ(1, ares_a_reply_ex_get_alias_count(reply));
  EXPECT_STREQ("query.example.com", ares_a_reply_ex_get_alias(reply, 0));
  EXPECT_EQ(AF_INET, ares_a_reply_ex_get_addr_type(reply));
  EXPECT_EQ(sizeof(struct in_addr), ares_a_reply_ex_get_length(reply));
  EXPECT_EQ(4, ares_a_reply_ex_get_addr_count(reply));

//   EXPECT_EQ(4, count);
//   EXPECT_EQ("129.97.123.221", AddressToString(&(info[0].ipaddr), 4));
//   EXPECT_EQ("129.97.123.222", AddressToString(&(info[1].ipaddr), 4));
//   EXPECT_EQ("129.97.123.223", AddressToString(&(info[2].ipaddr), 4));
//   EXPECT_EQ("129.97.123.224", AddressToString(&(info[3].ipaddr), 4));
//   EXPECT_EQ(300, info[0].ttl);
//   EXPECT_EQ(300, info[1].ttl);
//   EXPECT_EQ(300, info[2].ttl);
//   EXPECT_EQ(300, info[3].ttl);
//   ares_free_hostent(host);

  ares_free_a_reply(reply);
}

TEST_F(LibraryTest, ParseAReplyExErrors) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSARR("example.com", 100, {0x02, 0x03, 0x04, 0x05}));

  std::vector<byte> data;
  ares_a_reply *reply = nullptr;

  // No question.
  pkt.questions_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);

  pkt.add_question(new DNSQuestion("example.com", ns_t_a));

  // Question != answer
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("Axample.com", ns_t_a));

  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_a));

#ifdef DISABLED
  // Not a response.
  pkt.set_response(false);
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.set_response(true);

  // Bad return code.
  pkt.set_rcode(ns_r_formerr);
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply(data.data(), data.size(),
                                              &host, info, &count));
  EXPECT_EQ(nullptr, host);
  pkt.set_rcode(ns_r_noerror);
#endif

  // Two questions
  pkt.add_question(new DNSQuestion("example.com", ns_t_a));
  data = pkt.data();
  EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);
  pkt.questions_.clear();
  pkt.add_question(new DNSQuestion("example.com", ns_t_a));

  // Wrong sort of answer.
  pkt.answers_.clear();
  pkt.add_answer(new DNSMxRR("example.com", 100, 100, "mx1.example.com"));
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);
  pkt.answers_.clear();
  pkt.add_answer(new DNSARR("example.com", 100, {0x02, 0x03, 0x04, 0x05}));

  // No answer.
  pkt.answers_.clear();
  data = pkt.data();
  EXPECT_EQ(ARES_ENODATA, ares_parse_a_reply_ex(data.data(), data.size(), &reply));
  EXPECT_EQ(nullptr, reply);
  pkt.add_answer(new DNSARR("example.com", 100, {0x02, 0x03, 0x04, 0x05}));

  // Truncated packets.
  data = pkt.data();
  for (size_t len = 1; len < data.size(); len++) {
    EXPECT_EQ(ARES_EBADRESP, ares_parse_a_reply_ex(data.data(), len, &reply));
    EXPECT_EQ(nullptr, reply);
  }
}

TEST_F(LibraryTest, ParseAReplyExAllocFail) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", ns_t_a))
    .add_answer(new DNSCnameRR("example.com", 300, "c.example.com"))
    .add_answer(new DNSARR("c.example.com", 500, {0x02, 0x03, 0x04, 0x05}));

  std::vector<byte> data = pkt.data();
  ares_a_reply *reply = nullptr;

  for (int ii = 1; ii <= 8; ii++) {
    ClearFails();
    SetAllocFail(ii);
    EXPECT_EQ(ARES_ENOMEM, ares_parse_a_reply_ex(data.data(), data.size(), &reply)) << ii;
    EXPECT_EQ(nullptr, reply);
  }
}

}  // namespace test
}  // namespace ares
